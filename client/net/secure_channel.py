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


class SecureChannel:
    """Cifra e decifra mensagens sobre um Transport TCP.

    Responsabilidades únicas:
    - Handshake DH inicial (deriva dh_shared, gx_bytes, gy_bytes)
    - encrypt(bytes) → bytes  (contador c2s + AES-256-GCM)
    - decrypt(bytes) → Message (contador s2c + AES-256-GCM)
    - update_key(new_shared) — chamado pelo ConnectionActor após REKEY_RESP

    NÃO decide quando rekeiar, NÃO coordena threads, NÃO conhece Message além
    do necessário para deserializar o plaintext.
    """

    def __init__(self, transport: Transport, server_cert_path: str):
        self._transport       = transport
        self._server_cert_path = server_cert_path
        self._dh_shared: bytes | None = None
        self._n_send: int = 0
        self._n_recv: int = 0
        self._gx_bytes: bytes | None = None
        self._gy_bytes: bytes | None = None

    # ── Handshake ─────────────────────────────────────────────────────────────

    def dh_handshake(self) -> tuple[bytes, bytes]:
        """STS handshake com o servidor. Devolve (gx_bytes, gy_bytes)."""
        server_cert = crypto.cert_load(self._server_cert_path)
        server_pub  = crypto.cert_get_public_key(server_cert)

        dh_priv, gx_bytes = crypto.dh_generate_keypair()
        _clog.debug(f"[DH] g^x gerado: {len(gx_bytes)} bytes")
        self._transport.send(gx_bytes)

        response = self._transport.recv()
        gy_bytes, sig = crypto.unpair(response)
        crypto.rsa_verify(server_pub, sig, gx_bytes + gy_bytes)
        _clog.debug("[DH] certificado e assinatura do servidor verificados OK")

        self._dh_shared = crypto.dh_compute_shared(dh_priv, gy_bytes)
        self._n_send    = 0
        self._n_recv    = 0
        self._gx_bytes  = gx_bytes
        self._gy_bytes  = gy_bytes
        return gx_bytes, gy_bytes

    def update_key(self, new_shared: bytes) -> None:
        """Instala nova chave DH após rekey concluído. Repõe contadores."""
        self._dh_shared = new_shared
        self._n_send    = 0
        self._n_recv    = 0

    # ── Cifra / Decifra ───────────────────────────────────────────────────────

    def encrypt(self, msg_bytes: bytes) -> bytes:
        """Cifra msg_bytes com a chave c2s do próximo contador. Thread-unsafe —
        deve ser chamado apenas pela thread escritora do ConnectionActor."""
        self._n_send += 1
        key   = crypto.hkdf_derive(self._dh_shared, f"c2s-msg-{self._n_send}".encode())
        nonce = self._n_send.to_bytes(12, "big")
        return crypto.encrypt_counter(key, nonce, msg_bytes)

    def decrypt(self, raw: bytes) -> Message:
        """Decifra raw com a chave s2c do próximo contador. Thread-unsafe —
        deve ser chamado apenas pela thread leitora do ConnectionActor."""
        nonce    = raw[:12]
        expected = (self._n_recv + 1).to_bytes(12, "big")
        if nonce != expected:
            raise ValueError("Contador de sequência inválido — possível replay.")
        self._n_recv += 1
        key       = crypto.hkdf_derive(self._dh_shared, f"s2c-msg-{self._n_recv}".encode())
        plaintext = crypto.decrypt_counter(key, raw)
        return Message.deserialize(plaintext.decode("utf-8"))

    # ── Transport ─────────────────────────────────────────────────────────────

    def send_raw(self, data: bytes) -> None:
        self._transport.send(data)

    def recv_raw(self) -> bytes:
        return self._transport.recv()

    def disconnect(self) -> None:
        self._dh_shared = None
        self._n_send    = 0
        self._n_recv    = 0
        self._gx_bytes  = None
        self._gy_bytes  = None
        self._transport.disconnect()

    # ── Propriedades ──────────────────────────────────────────────────────────

    @property
    def dh_shared(self) -> bytes | None: return self._dh_shared

    @property
    def gx_bytes(self) -> bytes | None: return self._gx_bytes

    @property
    def gy_bytes(self) -> bytes | None: return self._gy_bytes

    @property
    def n_send(self) -> int: return self._n_send
