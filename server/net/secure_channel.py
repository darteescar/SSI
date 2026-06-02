import sys
import os

_SERVER_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SERVER_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.transport import Transport
from common.Message import Message
from common import crypto


class SecureChannel:
    def __init__(self, transport: Transport):
        self._transport = transport
        self._dh_shared: bytes | None = None
        self._n_send: int = 0
        self._n_recv: int = 0

    def establish(self, shared: bytes) -> None:
        self._dh_shared = shared
        self._n_send    = 0
        self._n_recv    = 0
        print(f"[DH] dh_shared={shared[:8].hex()}")

    def update_epoch(self, new_shared: bytes) -> None:
        self._dh_shared = new_shared
        self._n_recv    = 0
        self._n_send    = 0
        print(f"[REKEY] nova epoch com {self._transport.addr} — dh_shared={new_shared[:8].hex()}")

    def _key_c2s(self, n: int) -> bytes:
        return crypto.hkdf_derive(self._dh_shared, f"c2s-msg-{n}".encode())

    def _key_s2c(self, n: int) -> bytes:
        return crypto.hkdf_derive(self._dh_shared, f"s2c-msg-{n}".encode())

    @staticmethod
    def _counter_nonce(n: int) -> bytes:
        return n.to_bytes(12, "big")

    def send(self, msg: Message) -> None:
        if self._dh_shared is None:
            raise RuntimeError("Canal não estabelecido.")
        self._n_send += 1
        key   = self._key_s2c(self._n_send)
        nonce = self._counter_nonce(self._n_send)
        data  = msg.serialize().encode("utf-8")
        self._transport.send(crypto.encrypt_counter(key, nonce, data))

    def recv(self) -> Message:
        if self._dh_shared is None:
            raise RuntimeError("Canal não estabelecido.")
        raw   = self._transport.recv()
        nonce = raw[:12]
        expected = self._counter_nonce(self._n_recv + 1)
        if nonce != expected:
            raise ValueError(f"Contador de sequência inválido — possível replay.")
        self._n_recv += 1
        key       = self._key_c2s(self._n_recv)
        plaintext = crypto.decrypt_counter(key, raw)
        return Message.deserialize(plaintext.decode("utf-8"))

    def send_raw(self, data: bytes) -> None:
        self._transport.send(data)

    def recv_raw(self) -> bytes:
        return self._transport.recv()

    def close(self) -> None:
        self._transport.close()
