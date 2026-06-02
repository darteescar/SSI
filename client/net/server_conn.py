"""ServerConnection — camada de comunicação com o servidor.

Responsabilidades:
- Estabelecer e terminar a ligação TCP + handshake DH
- Cifrar/decifrar mensagens (via SecureChannel)
- Demultiplexar mensagens recebidas por tag (via Demultiplexer)
- Expor send() / receive(tag) / send_ack() / send_async()

NÃO sabe nada de: utilizadores, E2E, grupos, prekeys.
"""

import base64
import logging
import os
import sys
import threading

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

import common.crypto as crypto
from common.Message import Message
from common.MsgType import MsgType
from common.transport import Transport
from net.secure_channel import SecureChannel
from net.demultiplexer import Demultiplexer, TAG_RESPONSE

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
    """Canal seguro com o servidor + demultiplexação de mensagens."""

    def __init__(self):
        self._transport:     Transport      | None = None
        self._channel:       SecureChannel  | None = None
        self._demux:         Demultiplexer  | None = None
        self.gx_bytes: bytes | None = None
        self.gy_bytes: bytes | None = None

    # ── Ligação ───────────────────────────────────────────────────────────────

    def connect(self) -> None:
        self._transport = Transport.connect(HOST, PORT)
        self._channel   = SecureChannel(self._transport, SERVER_CERT_PATH)
        gx, gy = self._channel.dh_handshake()
        self.gx_bytes = gx
        self.gy_bytes = gy
        self._demux = Demultiplexer(self._channel)
        self._demux._init_async_tracking()
        self._demux.start()

    def disconnect(self) -> None:
        if self._demux:
            self._demux.close()
        if self._channel:
            self._channel.disconnect()
        self._transport = None
        self._channel   = None
        self._demux     = None
        self.gx_bytes   = None
        self.gy_bytes   = None
        set_logger_user(None)

    def is_connected(self) -> bool:
        return self._transport is not None and self._transport.socket is not None

    @property
    def dh_shared(self):
        return self._channel.dh_shared if self._channel else None

    # ── Envio / Recepção ──────────────────────────────────────────────────────

    def send(self, msg: Message) -> None:
        if not self._channel:
            raise RuntimeError("Sem canal seguro.")
        self._channel.check_rekey()
        self._demux.send(msg)

    def receive(self, tag: int = TAG_RESPONSE) -> Message | None:
        if not self._demux:
            return None
        return self._demux.receive(tag)

    def send_ack(self, msg: Message) -> None:
        """Envia ACK sem triggering de rekey (chamado da receive thread)."""
        if not self._channel or self._channel.is_rekeying:
            return
        try:
            self._demux.send(msg)
        except OSError:
            pass

    def send_async(self, msg: Message) -> None:
        """Envia mensagem da receive thread; regista msg_id para descartar o OK."""
        if not self._channel or self._channel.is_rekeying:
            return
        mid = msg.get("msg_id") or (msg.payload.get("msg_id") if hasattr(msg, "payload") else None)
        if mid:
            self._demux.register_async_id(str(mid))
        try:
            self._demux.send(msg)
        except OSError:
            if mid:
                self._demux._discard_async(str(mid))
