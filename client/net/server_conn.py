"""ServerConnection — API de comunicação com o servidor.

Responsabilidades:
- Estabelecer e terminar a ligação TCP + handshake DH inicial
- Expor send() / receive(tag) como interface bloqueante para MessagingService
- Expor send_ack() / send_async() para envios fire-and-forget

NÃO sabe nada de: utilizadores, E2E, grupos, prekeys, rekey, cifra.
"""

import logging
import os
import sys

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.transport import Transport
from net.secure_channel import SecureChannel
from net.connection import ConnectionActor, TAG_RESPONSE, TAG_E2E, TAG_CHAT, TAG_GROUP_EVT

_LOG_PATH = os.path.join(_CLIENT_DIR, "e2e.log")
_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)-5s] %(name)-9s user=%(user)-10s — %(message)s",
    datefmt="%H:%M:%S",
)
_current_user = {"user": "-"}


def set_logger_user(username: str | None) -> None:
    _current_user["user"] = username or "-"


class _UserFilter(logging.Filter):
    def filter(self, record):
        record.user = _current_user["user"]
        return True


def _setup_logger(name: str) -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        lg.setLevel(logging.DEBUG)
        fh = logging.FileHandler(_LOG_PATH, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_fmt)
        fh.addFilter(_UserFilter())
        lg.addHandler(fh)
    return lg


_setup_logger("network")
_setup_logger("e2e")
_setup_logger("keystore")

HOST = "127.0.0.1"
PORT = 6767
_DATA_DIR        = os.path.join(_CLIENT_DIR, "data")
SERVER_CERT_PATH = os.path.join(_DATA_DIR, "ca", "server.crt")


class ServerConnection:
    """Canal seguro com o servidor.

    Delega cifra ao SecureChannel e coordenação de threads ao ConnectionActor.
    Expõe apenas send/receive para as camadas superiores.
    """

    def __init__(self):
        self._transport: Transport      | None = None
        self._channel:   SecureChannel  | None = None
        self._actor:     ConnectionActor | None = None
        self.gx_bytes:   bytes | None = None
        self.gy_bytes:   bytes | None = None
        self.username:   str   | None = None

    # ── Ligação ───────────────────────────────────────────────────────────────

    def connect(self) -> None:
        self._transport = Transport.connect(HOST, PORT)
        self._channel   = SecureChannel(self._transport, SERVER_CERT_PATH)
        gx, gy          = self._channel.dh_handshake()
        self.gx_bytes   = gx
        self.gy_bytes   = gy
        self._actor     = ConnectionActor(self._channel)
        self._actor.start()

    def disconnect(self) -> None:
        if self._actor:
            self._actor.close()
        self._transport = None
        self._channel   = None
        self._actor     = None
        self.gx_bytes   = None
        self.gy_bytes   = None
        self.username   = None
        set_logger_user(None)

    def is_connected(self) -> bool:
        return self._transport is not None and self._transport.socket is not None

    @property
    def dh_shared(self) -> bytes | None:
        return self._channel.dh_shared if self._channel else None

    # ── Envio / Recepção ──────────────────────────────────────────────────────

    def send(self, msg: Message) -> Message | None:
        """Envia msg e bloqueia até receber a resposta síncrona."""
        if not self._actor:
            raise RuntimeError("Sem ligação.")
        return self._actor.request(msg)

    def receive(self, tag: int = TAG_RESPONSE) -> Message | None:
        """Bloqueia até haver uma mensagem push na fila da tag dada."""
        if not self._actor:
            return None
        return self._actor.receive_push(tag)

    def send_ack(self, msg: Message) -> None:
        """Envia ACK sem esperar resposta (chamado da receive thread)."""
        if not self._actor:
            return
        try:
            self._actor.push_send(msg)
        except OSError:
            pass

    def send_async(self, msg: Message) -> None:
        """Envia mensagem fire-and-forget (dh_resp, sk_dist)."""
        if not self._actor:
            return
        try:
            self._actor.push_send(msg)
        except OSError:
            pass
