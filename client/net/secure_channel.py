import threading
import logging
import os
import sys
_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.transport import Transport
import common.crypto as crypto
from common.Message import Message

_clog = logging.getLogger("crypto")

REKEY_INTERVAL = 10

class SecureChannel:
    def __init__(self, transport: Transport, server_cert_path: str):
        self.transport = transport
        self.server_cert_path = server_cert_path

        self._dh_shared: bytes | None = None
        self._n_send: int = 0
        self._n_recv: int = 0
        self._gx_bytes: bytes | None = None
        self._gy_bytes: bytes | None = None

        self._pending_rekey_priv = None
        self._rekey_done = threading.Event()
        self._rekeying = False

        self._send_lock = threading.Lock()

    def disconnect(self):
        self._dh_shared = None
        self._n_send = 0
        self._n_recv = 0
        self._gx_bytes = None
        self._gy_bytes = None
        self._pending_rekey_priv = None
        self._rekeying = False
        self.transport.disconnect()

    def _key_c2s(self, n: int) -> bytes:
        return crypto.hkdf_derive(self._dh_shared, f"c2s-msg-{n}".encode())

    def _key_s2c(self, n: int) -> bytes:
        return crypto.hkdf_derive(self._dh_shared, f"s2c-msg-{n}".encode())

    def dh_handshake(self) -> tuple[bytes, bytes]:
        server_cert_local = crypto.cert_load(self.server_cert_path)
        server_pubkey     = crypto.cert_get_public_key(server_cert_local)

        dh_priv, gx_bytes = crypto.dh_generate_keypair()
        _clog.debug(f"[DH] g^x gerado: {len(gx_bytes)} bytes")
        self.transport.send(gx_bytes)

        response = self.transport.recv()
        gy_bytes, sig_servidor = crypto.unpair(response)

        crypto.rsa_verify(server_pubkey, sig_servidor, gx_bytes + gy_bytes)
        _clog.debug("[DH] certificado e assinatura do servidor verificados OK")

        self._dh_shared = crypto.dh_compute_shared(dh_priv, gy_bytes)
        self._n_send    = 0
        self._n_recv    = 0
        self._gx_bytes  = gx_bytes
        self._gy_bytes  = gy_bytes

        return gx_bytes, gy_bytes

    @staticmethod
    def _counter_nonce(n: int) -> bytes:
        return n.to_bytes(12, "big")

    def send_encrypted(self, msg_bytes: bytes):
        with self._send_lock:
            self._n_send += 1
            key   = self._key_c2s(self._n_send)
            nonce = self._counter_nonce(self._n_send)
            self.transport.send(crypto.encrypt_counter(key, nonce, msg_bytes))

    def _recv_encrypted_raw(self) -> Message:
        raw   = self.transport.recv()
        nonce = raw[:12]
        expected = self._counter_nonce(self._n_recv + 1)
        if nonce != expected:
            raise ValueError("Contador de sequência inválido — possível replay.")
        self._n_recv += 1
        key       = self._key_s2c(self._n_recv)
        plaintext = crypto.decrypt_counter(key, raw)
        return Message.deserialize(plaintext.decode("utf-8"))

    def recv_encrypted(self) -> Message:
        return self._recv_encrypted_raw()

    def initiate_rekey(self):
        new_priv, new_gx = crypto.dh_generate_keypair()
        self._pending_rekey_priv = new_priv
        self._rekey_done.clear()
        self._rekeying = True

        try:
            self.send_encrypted(Message.req_rekey(new_gx).serialize().encode("utf-8"))
            if not self._rekey_done.wait(timeout=10):
                raise TimeoutError("Timeout a aguardar REKEY_RESP do servidor.")
        finally:
            self._rekeying = False

    def handle_rekey_response(self, new_gy_bytes: bytes):
        new_shared = crypto.dh_compute_shared(self._pending_rekey_priv, new_gy_bytes)
        self._dh_shared = new_shared
        self._n_send = 0
        self._n_recv = 0
        self._pending_rekey_priv = None
        self._rekey_done.set()

    def check_rekey(self):
        if self._n_send > 0 and self._n_send % REKEY_INTERVAL == 0:
            self.initiate_rekey()

    @property
    def dh_shared(self): return self._dh_shared

    @property
    def gx_bytes(self): return self._gx_bytes

    @property
    def gy_bytes(self): return self._gy_bytes

    @property
    def is_rekeying(self): return self._rekeying
