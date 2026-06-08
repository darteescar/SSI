"""ClientConnection — thread escritora + thread leitora por cliente, com os
pedidos a serem executados num thread pool partilhado.

Arquitectura de threads (por cliente)
-------------------------------------
  Writer thread   — único produtor do socket deste cliente.
                    Consome _send_queue e escreve cada frame cifrado.
                    Quando uma entrada da fila traz uma nova chave de epoch
                    (resposta a REKEY), aplica channel.update_key() DEPOIS de
                    enviar essa entrada — garantindo que a resposta vai com a
                    chave antiga e tudo a seguir com a nova.

  Reader thread   — único consumidor do socket deste cliente.
                    Decifra cada frame e:
                      • REKEY  → gera novo g^y, calcula novo segredo, enfileira
                                 RESP_REKEY marcada com a nova chave e bloqueia
                                 até a Writer confirmar a troca de epoch
                      • resto  → submete o processamento ao thread pool partilhado

Thread pool (partilhado por todos os clientes)
----------------------------------------------
  Os pedidos são executados por pool.submit(_process, msg). O handler nunca
  escreve no socket: chama session.send(resp) → connection.push_send(resp),
  que enfileira na _send_queue. A Writer é a única a escrever.

  Para preservar a ORDEM de processamento de um mesmo cliente (importante para
  o contador de nonce e para a coerência de estado), os pedidos desse cliente
  são serializados: a Reader só submete o pedido seguinte depois de o anterior
  terminar (via _processing_done).
"""

import base64
import logging
import threading
from collections import deque

import sys
import os

_SERVER_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SERVER_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.MsgType import MsgType
from common import crypto
from net.secure_channel import SecureChannel

_session = logging.getLogger("session")
_dh      = logging.getLogger("dh")


class _QueueItem:
    """Entrada da fila de envio. new_key != None marca uma troca de epoch
    a aplicar imediatamente após o envio deste frame."""
    __slots__ = ("msg", "new_key")

    def __init__(self, msg: Message, new_key: bytes | None = None):
        self.msg     = msg
        self.new_key = new_key


class ClientConnection:
    """Gere as duas threads (writer/reader) de um cliente e despacha os
    pedidos para o thread pool partilhado."""

    def __init__(self, channel: SecureChannel, pool, on_message, on_eof):
        self._channel = channel
        self._pool    = pool          # ThreadPoolExecutor partilhado
        self._on_message = on_message # callable(msg) — executado no pool
        self._on_eof     = on_eof     # callable() — chamado quando o cliente fecha

        # Fila de envio — partilhada entre handlers (via pool) e Writer
        self._send_lock  = threading.Lock()
        self._send_cond  = threading.Condition(self._send_lock)
        self._send_queue: deque[_QueueItem] = deque()

        # Serialização do processamento de pedidos deste cliente
        self._processing_done = threading.Event()
        self._processing_done.set()
        self._current_rid: str | None = None  # _rid (request id) do pedido em curso

        # Sinaliza que a Writer concluiu uma troca de epoch (rekey)
        self._epoch_switched = threading.Event()

        self._closed   = False
        self._draining = False   # fecho gracioso: drenar a fila antes de fechar
        self._writer_thread: threading.Thread | None = None
        self._reader_thread: threading.Thread | None = None

    # ── Ciclo de vida ─────────────────────────────────────────────────────────

    def start(self) -> None:
        self._writer_thread = threading.Thread(
            target=self._writer, name="Cli-Writer", daemon=True
        )
        self._reader_thread = threading.Thread(
            target=self._reader, name="Cli-Reader", daemon=True
        )
        self._writer_thread.start()
        self._reader_thread.start()

    def join(self) -> None:
        """Bloqueia até a leitura terminar (cliente desligou-se)."""
        if self._reader_thread:
            self._reader_thread.join()

    def close(self) -> None:
        """Fecho imediato — descarta o que estiver na fila."""
        self._closed = True
        with self._send_cond:
            self._send_cond.notify_all()
        try:
            self._channel.close()
        except Exception:
            pass

    def shutdown_graceful(self) -> None:
        """Pede à Writer que envie tudo o que está na fila e só depois feche.
        Usado no logout, para garantir a entrega da resp_logout."""
        with self._send_cond:
            self._draining = True
            self._send_cond.notify_all()

    # ── API pública ───────────────────────────────────────────────────────────

    def reply(self, msg: Message) -> None:
        """Resposta ao próprio cliente. Ecoa o _rid (request id) do pedido em
        curso para que o cliente faça match no seu request()."""
        if self._current_rid is not None:
            msg.set("_rid", self._current_rid)
        self.push_send(msg)

    def push_send(self, msg: Message) -> None:
        """Enfileira msg para a Writer enviar (sem ecoar _rid). Usado para
        pushes vindos de outros clientes."""
        with self._send_cond:
            self._send_queue.append(_QueueItem(msg))
            self._send_cond.notify()

    # ── Thread escritora ──────────────────────────────────────────────────────

    def _writer(self) -> None:
        try:
            while not self._closed:
                with self._send_cond:
                    while not self._send_queue and not self._closed and not self._draining:
                        self._send_cond.wait()
                    if self._closed:
                        break
                    if not self._send_queue and self._draining:
                        # fila drenada após pedido de fecho gracioso
                        break
                    item = self._send_queue.popleft()

                encrypted = self._channel.encrypt(item.msg.serialize().encode("utf-8"))
                self._channel.send_raw(encrypted)

                # Troca de epoch: aplica a nova chave logo após enviar a resposta
                if item.new_key is not None:
                    self._channel.update_key(item.new_key)
                    self._epoch_switched.set()  # desbloqueia a Reader
                    _dh.info("renegociação DH concluída — nova epoch instalada")

        except Exception as e:
            if not self._closed:
                _session.error(f"[Writer] erro ao enviar: {e}")
        finally:
            # Saída do loop (drain concluído ou erro): fecha o canal, o que faz
            # a Reader sair e disparar o _on_eof.
            self.close()

    # ── Thread leitora ────────────────────────────────────────────────────────

    def _reader(self) -> None:
        try:
            while not self._closed:
                raw = self._channel.recv_raw()
                msg = self._channel.decrypt(raw)

                if msg.type == MsgType.REKEY:
                    self._handle_rekey(msg)
                    continue

                # Serializa: espera o pedido anterior terminar antes de submeter
                self._processing_done.wait()
                self._processing_done.clear()
                self._current_rid = msg.get("_rid")
                self._pool.submit(self._process, msg)

        except Exception as e:
            if not self._closed:
                _session.debug(f"socket fechado pelo cliente: {e}")
        finally:
            self._on_eof()
            self.close()

    def _process(self, msg: Message) -> None:
        """Executado no thread pool. Processa um pedido e liberta o próximo."""
        try:
            self._on_message(msg)
        except (ConnectionResetError, ConnectionAbortedError):
            # logout ou fim de sessão: deixa a Writer drenar (entregar resp_logout)
            self._processing_done.set()
            self.shutdown_graceful()
            return
        except Exception as e:
            _session.error(f"erro ao processar mensagem {msg.type}: {e}", exc_info=True)
        finally:
            self._processing_done.set()

    def _handle_rekey(self, msg: Message) -> None:
        """Responde a um REKEY iniciado pelo cliente. A troca de chave é feita
        pela Writer, após enviar a resposta — coordenada via _processing_done."""
        try:
            new_gx           = base64.b64decode(msg.get("gx"))
            new_priv, new_gy = crypto.dh_generate_keypair()
            new_shared       = crypto.dh_compute_shared(new_priv, new_gx)
        except Exception as e:
            _session.error(f"renegociação DH falhou: {e}")
            self.close()
            return

        # Garante que nenhum pedido está a ser processado durante a troca:
        # o contador de envio (s2c) não pode avançar enquanto a epoch muda.
        self._processing_done.wait()

        # Enfileira a resposta marcada com a nova chave; a Writer aplica a troca
        # de epoch depois de enviar a resposta (cifrada ainda com a chave antiga).
        self._epoch_switched.clear()
        with self._send_cond:
            self._send_queue.append(_QueueItem(Message.resp_rekey(new_gy), new_key=new_shared))
            self._send_cond.notify()

        # Bloqueia até a Writer concluir a troca, para não decifrar frames novos
        # (que virão com a chave nova) antes de update_key().
        self._epoch_switched.wait()
