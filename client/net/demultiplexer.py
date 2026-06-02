"""Demultiplexer — lê mensagens do SecureChannel em background e distribui-as
por filas indexadas por tag inteira.

Tags usadas pelo sistema:
    TAG_RESPONSE  = 0  — respostas síncronas (OK / ERROR) a pedidos do utilizador
    TAG_E2E       = 1  — E2E_DELIVER (push do servidor)
    TAG_CHAT      = 2  — RECEIVE / GROUP_RECEIVE (push do servidor)
    TAG_GROUP_EVT = 3  — GROUP_MEMBER_LEFT / GROUP_MEMBER_JOINED (push do servidor)
"""

import threading
import logging
from collections import deque

import sys, os
_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.MsgType import MsgType

_log = logging.getLogger("network")

TAG_RESPONSE  = 0
TAG_E2E       = 1
TAG_CHAT      = 2
TAG_GROUP_EVT = 3

_PUSH_TAGS: dict[MsgType, int] = {
    MsgType.E2E_DELIVER:        TAG_E2E,
    MsgType.RECEIVE:            TAG_CHAT,
    MsgType.GROUP_RECEIVE:      TAG_CHAT,
    MsgType.GROUP_MEMBER_LEFT:  TAG_GROUP_EVT,
    MsgType.GROUP_MEMBER_JOINED: TAG_GROUP_EVT,
}


class _Entry:
    __slots__ = ("queue", "cond")

    def __init__(self, lock: threading.RLock):
        self.queue: deque[Message] = deque()
        self.cond = threading.Condition(lock)


class Demultiplexer:
    """Demultiplexa mensagens recebidas do SecureChannel para filas por tag.

    A thread de background corre até ao close() ou até o canal fechar.
    send() e receive(tag) podem ser chamados de qualquer thread.
    """

    def __init__(self, channel):
        self._channel   = channel
        self._lock      = threading.RLock()
        self._entries:  dict[int, _Entry] = {}
        self._closed    = False
        self._exception: Exception | None = None
        self._thread:   threading.Thread | None = None

    def _get_entry(self, tag: int) -> _Entry:
        if tag not in self._entries:
            self._entries[tag] = _Entry(self._lock)
        return self._entries[tag]

    # ── Ciclo de vida ─────────────────────────────────────────────────────────

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._background, name="Demultiplexer", daemon=True
        )
        self._thread.start()

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for entry in self._entries.values():
                with entry.cond:
                    entry.cond.notify_all()

    # ── Interface pública ─────────────────────────────────────────────────────

    def send(self, msg: Message) -> None:
        """Envia uma mensagem pelo canal seguro (thread-safe via _send_lock do canal)."""
        self._channel.send_encrypted(msg.serialize().encode("utf-8"))

    def send_raw(self, data: bytes) -> None:
        """Envia bytes em bruto (usado no handshake DH antes da cifra)."""
        self._channel.transport.send(data)

    def receive(self, tag: int) -> Message | None:
        """Bloqueia até haver uma mensagem na fila da tag dada.
        Devolve None se o demultiplexer fechar ou ocorrer uma excepção."""
        with self._lock:
            entry = self._get_entry(tag)
            with entry.cond:
                while not entry.queue and not self._closed and self._exception is None:
                    entry.cond.wait()
                if self._closed or self._exception is not None:
                    return None
                return entry.queue.popleft()

    # ── Thread de background ──────────────────────────────────────────────────

    def _background(self) -> None:
        import base64
        try:
            while True:
                with self._lock:
                    if self._closed:
                        break

                msg = self._channel.recv_encrypted()

                # rekey tratado aqui — transparente para as camadas superiores
                if msg.type == MsgType.REKEY:
                    new_gy = base64.b64decode(msg.get("gy"))
                    self._channel.handle_rekey_response(new_gy)
                    continue

                tag = _PUSH_TAGS.get(msg.type, TAG_RESPONSE)

                # OKs de mensagens enviadas em modo async (dh_resp, sk_dist)
                # têm msg_id registado — são descartados aqui
                if msg.type == MsgType.OK:
                    mid = msg.get("msg_id")
                    if mid and self._discard_async(str(mid)):
                        continue

                with self._lock:
                    entry = self._get_entry(tag)
                    with entry.cond:
                        entry.queue.append(msg)
                        entry.cond.notify_all()

        except Exception as e:
            _log.error(f"[Demultiplexer] excepção na thread de background: {e}")
            with self._lock:
                self._exception = e
                for entry in self._entries.values():
                    with entry.cond:
                        entry.cond.notify_all()

    # ── Async msg-id tracking (para send_async) ───────────────────────────────

    def _init_async_tracking(self) -> None:
        self._async_ids: set[str] = set()
        self._async_lock = threading.Lock()

    def register_async_id(self, mid: str) -> None:
        with self._async_lock:
            self._async_ids.add(mid)

    def _discard_async(self, mid: str) -> bool:
        try:
            with self._async_lock:
                if mid in self._async_ids:
                    self._async_ids.discard(mid)
                    return True
        except AttributeError:
            pass
        return False
