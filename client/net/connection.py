"""ConnectionActor — thread escritora + thread leitora + gestão de rekey.

Arquitectura de threads
-----------------------
  Writer thread   — único produtor do socket de escrita.
                    Consome _send_queue, cifra e envia cada frame.
                    Ao atingir REKEY_INTERVAL mensagens enviadas, envia REKEY,
                    marca _rekey_pending e bloqueia até a Reader assinalar
                    _rekey_done (após receber REKEY_RESP do servidor).

  Reader thread   — único consumidor do socket de leitura.
                    Decifra cada frame, classifica por tipo e:
                      • REKEY_RESP  → actualiza a chave no canal + sinaliza Writer
                      • push tags   → coloca na fila de push (TAG_E2E/CHAT/GROUP_EVT)
                      • resto       → tenta fazer match com um slot de pedido pendente
                                      pelo msg_id; se não houver, usa TAG_RESPONSE

Pedidos síncronos (request)
---------------------------
  request(msg) coloca msg na _send_queue com um slot (Condition + resultado),
  bloqueia no slot até a Reader colocar a resposta, e devolve-a.

Pedidos fire-and-forget (push_send)
------------------------------------
  push_send(msg) coloca msg na _send_queue sem slot — a Writer envia-a e
  nenhuma thread fica à espera de resposta (usado para ACKs e sends assíncronos).

Tags de push
------------
  TAG_RESPONSE  = 0   respostas síncronas sem msg_id conhecido (fallback)
  TAG_E2E       = 1   E2E_DELIVER
  TAG_CHAT      = 2   RECEIVE / GROUP_RECEIVE
  TAG_GROUP_EVT = 3   GROUP_MEMBER_LEFT / GROUP_MEMBER_JOINED
"""

import base64
import logging
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import sys
import os

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.MsgType import MsgType
from net.secure_channel import SecureChannel
import common.crypto as crypto

_log = logging.getLogger("network")

REKEY_INTERVAL = 10

# ── Tags de push ──────────────────────────────────────────────────────────────

TAG_RESPONSE  = 0
TAG_E2E       = 1
TAG_CHAT      = 2
TAG_GROUP_EVT = 3

_PUSH_TYPE_TO_TAG: dict[MsgType, int] = {
    MsgType.E2E_DELIVER:         TAG_E2E,
    MsgType.RECEIVE:             TAG_CHAT,
    MsgType.GROUP_RECEIVE:       TAG_CHAT,
    MsgType.GROUP_MEMBER_LEFT:   TAG_GROUP_EVT,
    MsgType.GROUP_MEMBER_JOINED: TAG_GROUP_EVT,
}


# ── Estruturas internas ───────────────────────────────────────────────────────

@dataclass
class _RequestSlot:
    """Slot de espera para um pedido síncrono."""
    cond:   threading.Condition = field(default_factory=threading.Condition)
    result: Any = None          # preenchido pela Reader antes de notify


@dataclass
class _QueueItem:
    """Item na fila de envio."""
    frame: bytes                       # bytes já serializados (plaintext)
    slot:  _RequestSlot | None = None  # None para fire-and-forget


class _PushQueue:
    """Fila bloqueante para mensagens push de uma tag específica."""

    def __init__(self):
        self._lock  = threading.Lock()
        self._cond  = threading.Condition(self._lock)
        self._queue: deque[Message] = deque()
        self._closed = False

    def put(self, msg: Message) -> None:
        with self._cond:
            self._queue.append(msg)
            self._cond.notify()

    def get(self) -> Message | None:
        with self._cond:
            while not self._queue and not self._closed:
                self._cond.wait()
            if self._closed:
                return None
            return self._queue.popleft()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()


# ── ConnectionActor ───────────────────────────────────────────────────────────

class ConnectionActor:
    """Gere a thread escritora e a thread leitora sobre um SecureChannel.

    Coordena o rekey entre as duas threads sem expor esse detalhe para cima.
    """

    def __init__(self, channel: SecureChannel):
        self._channel = channel

        # Fila de envio — partilhada entre callers e Writer
        self._send_lock  = threading.Lock()
        self._send_cond  = threading.Condition(self._send_lock)
        self._send_queue: deque[_QueueItem] = deque()

        # Pedidos síncronos pendentes: msg_id → _RequestSlot
        self._pending_lock = threading.Lock()
        self._pending: dict[str, _RequestSlot] = {}

        # Filas de push por tag
        self._push_queues: dict[int, _PushQueue] = {
            TAG_RESPONSE:  _PushQueue(),
            TAG_E2E:       _PushQueue(),
            TAG_CHAT:      _PushQueue(),
            TAG_GROUP_EVT: _PushQueue(),
        }

        # Coordenação de rekey entre Writer e Reader
        self._rekey_lock    = threading.Lock()
        self._rekey_pending = False
        self._rekey_done    = threading.Condition(self._rekey_lock)
        self._rekey_priv    = None  # chave DH efémera gerada pela Writer

        self._closed = False
        self._writer_thread: threading.Thread | None = None
        self._reader_thread: threading.Thread | None = None

    # ── Ciclo de vida ─────────────────────────────────────────────────────────

    def start(self) -> None:
        self._writer_thread = threading.Thread(
            target=self._writer, name="Conn-Writer", daemon=True
        )
        self._reader_thread = threading.Thread(
            target=self._reader, name="Conn-Reader", daemon=True
        )
        self._writer_thread.start()
        self._reader_thread.start()

    def close(self) -> None:
        self._closed = True

        # Acorda Writer
        with self._send_cond:
            self._send_cond.notify_all()

        # Acorda Reader (via canal)
        try:
            self._channel.disconnect()
        except Exception:
            pass

        # Acorda todos os waiters de push
        for q in self._push_queues.values():
            q.close()

        # Acorda todos os slots de pedidos pendentes
        with self._pending_lock:
            for slot in self._pending.values():
                with slot.cond:
                    slot.cond.notify_all()

    # ── API pública ───────────────────────────────────────────────────────────

    def request(self, msg: Message) -> Message | None:
        """Envia msg e bloqueia até receber a resposta. Devolve None se fechado.

        Usa _rid (request id) no envelope — distinto do msg_id aplicacional
        (E2E, grupos), que tem outro significado. O servidor ecoa o _rid na
        resposta para fazermos o match aqui."""
        rid = str(uuid.uuid4())
        msg.set("_rid", rid)

        slot = _RequestSlot()
        with self._pending_lock:
            self._pending[rid] = slot

        frame = msg.serialize().encode("utf-8")
        item  = _QueueItem(frame=frame, slot=slot)

        with self._send_cond:
            self._send_queue.append(item)
            self._send_cond.notify()

        with slot.cond:
            while slot.result is None and not self._closed:
                slot.cond.wait()

        with self._pending_lock:
            self._pending.pop(rid, None)

        return slot.result

    def push_send(self, msg: Message) -> None:
        """Envia msg sem esperar resposta (ACKs, sends assíncronos)."""
        frame = msg.serialize().encode("utf-8")
        item  = _QueueItem(frame=frame, slot=None)
        with self._send_cond:
            self._send_queue.append(item)
            self._send_cond.notify()

    def receive_push(self, tag: int) -> Message | None:
        """Bloqueia até haver uma mensagem push na fila da tag dada."""
        q = self._push_queues.get(tag)
        if q is None:
            return None
        return q.get()

    # ── Thread escritora ──────────────────────────────────────────────────────

    def _writer(self) -> None:
        try:
            while not self._closed:
                with self._send_cond:
                    while not self._send_queue and not self._closed:
                        self._send_cond.wait()
                    if self._closed:
                        break
                    item = self._send_queue.popleft()

                # Bloqueia se há um rekey em curso iniciado pela mensagem anterior
                with self._rekey_lock:
                    while self._rekey_pending and not self._closed:
                        self._rekey_done.wait()

                if self._closed:
                    break

                encrypted = self._channel.encrypt(item.frame)
                self._channel.send_raw(encrypted)

                # Após enviar, verifica se atingimos o intervalo de rekey.
                # n_send foi incrementado dentro de encrypt().
                if (self._channel.n_send % REKEY_INTERVAL == 0
                        and not self._rekey_pending):
                    self._initiate_rekey()

                # Se for fire-and-forget, não há mais nada a fazer
                # Se for síncrono, a Reader tratará de acordar o slot

        except Exception as e:
            _log.error(f"[Writer] excepção: {e}")
            self._abort(e)

    def _initiate_rekey(self) -> None:
        """Gera novo par DH e envia REKEY. Chamado apenas pela Writer."""
        new_priv, new_gx = crypto.dh_generate_keypair()
        with self._rekey_lock:
            self._rekey_priv    = new_priv
            self._rekey_pending = True

        rekey_msg   = Message.req_rekey(new_gx)
        rekey_frame = rekey_msg.serialize().encode("utf-8")
        encrypted   = self._channel.encrypt(rekey_frame)
        self._channel.send_raw(encrypted)
        _log.debug("[Writer] REKEY enviado — a aguardar REKEY_RESP")

    # ── Thread leitora ────────────────────────────────────────────────────────

    def _reader(self) -> None:
        try:
            while not self._closed:
                raw = self._channel.recv_raw()
                msg = self._channel.decrypt(raw)

                if msg.type == MsgType.REKEY:
                    # Servidor inicia rekey (não esperado neste protocolo,
                    # mas trata-se por simetria)
                    new_gy = base64.b64decode(msg.get("gy"))
                    with self._rekey_lock:
                        new_shared = crypto.dh_compute_shared(self._rekey_priv, new_gy)
                        self._channel.update_key(new_shared)
                        self._rekey_priv    = None
                        self._rekey_pending = False
                        self._rekey_done.notify_all()
                    _log.debug("[Reader] REKEY_RESP processado — nova epoch instalada")
                    continue

                self._dispatch(msg)

        except Exception as e:
            if not self._closed:
                _log.error(f"[Reader] excepção: {e}")
                self._abort(e)

    def _dispatch(self, msg: Message) -> None:
        """Encaminha a mensagem para o slot de pedido correcto ou fila de push."""

        # Tenta fazer match com pedido síncrono pelo _rid (request id do envelope)
        rid = msg.get("_rid")
        if rid:
            with self._pending_lock:
                slot = self._pending.get(str(rid))
            if slot is not None:
                with slot.cond:
                    slot.result = msg
                    slot.cond.notify_all()
                return

        # Mensagem push (sem _rid correspondente a pedido pendente)
        tag = _PUSH_TYPE_TO_TAG.get(msg.type, TAG_RESPONSE)
        self._push_queues[tag].put(msg)

    # ── Erro fatal ────────────────────────────────────────────────────────────

    def _abort(self, exc: Exception) -> None:
        """Fecha tudo e acorda todos os waiters com result=None."""
        self._closed = True

        with self._send_cond:
            self._send_cond.notify_all()

        with self._rekey_lock:
            self._rekey_pending = False
            self._rekey_done.notify_all()

        for q in self._push_queues.values():
            q.close()

        with self._pending_lock:
            for slot in self._pending.values():
                with slot.cond:
                    slot.cond.notify_all()
