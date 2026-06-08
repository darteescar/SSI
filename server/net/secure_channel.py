import sys
import os
import logging

_SERVER_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SERVER_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.transport import Transport
from common.Message import Message
from common import crypto

_dh = logging.getLogger("dh")


class SecureChannel:
    """Cifra e decifra mensagens sobre um Transport TCP (lado servidor).

    Responsabilidades únicas:
    - Handshake DH inicial (responde ao g^x do cliente, deriva dh_shared)
    - encrypt(bytes) → bytes  (contador s2c + AES-256-GCM)
    - decrypt(bytes) → Message (contador c2s + AES-256-GCM)
    - update_key(new_shared) — chamado pela ClientConnection após REKEY

    Direcções invertidas em relação ao cliente: o servidor cifra com s2c e
    decifra com c2s. NÃO decide quando rekeiar, NÃO coordena threads.
    """

    def __init__(self, transport: Transport):
        self._transport = transport
        self._dh_shared: bytes | None = None
        self._n_send: int = 0
        self._n_recv: int = 0
        self._gx_bytes: bytes | None = None
        self._gy_bytes: bytes | None = None

    # ── Handshake ─────────────────────────────────────────────────────────────

    def dh_handshake(self, server_privkey) -> tuple[bytes, bytes]:
        """STS handshake: recebe g^x, responde com g^y assinado, deriva o segredo.
        Devolve (gx_bytes, gy_bytes)."""
        gx_bytes = self._transport.recv()

        dh_priv, gy_bytes = crypto.dh_generate_keypair()
        sig = crypto.rsa_sign(server_privkey, gx_bytes + gy_bytes)
        self._transport.send(crypto.mkpair(gy_bytes, sig))

        self._dh_shared = crypto.dh_compute_shared(dh_priv, gx_bytes)
        self._n_send    = 0
        self._n_recv    = 0
        self._gx_bytes  = gx_bytes
        self._gy_bytes  = gy_bytes
        _dh.info(f"handshake STS concluído com {self._transport.addr} — "
                 f"segredo partilhado derivado via DH, canal cifrado pronto "
                 f"(AES-256-GCM, chaves via HKDF-SHA256)")
        return gx_bytes, gy_bytes

    def update_key(self, new_shared: bytes) -> None:
        """Instala nova chave DH após rekey. Repõe contadores."""
        self._dh_shared = new_shared
        self._n_send    = 0
        self._n_recv    = 0

    # ── Cifra / Decifra ───────────────────────────────────────────────────────

    def encrypt(self, msg_bytes: bytes) -> bytes:
        """Cifra msg_bytes com a chave s2c do próximo contador. Thread-unsafe —
        deve ser chamado apenas pela thread escritora da ClientConnection."""
        if self._dh_shared is None:
            raise RuntimeError("Canal não estabelecido.")
        self._n_send += 1
        key   = crypto.hkdf_derive(self._dh_shared, f"s2c-msg-{self._n_send}".encode())
        nonce = self._n_send.to_bytes(12, "big")
        return crypto.encrypt_counter(key, nonce, msg_bytes)

    def decrypt(self, raw: bytes) -> Message:
        """Decifra raw com a chave c2s do próximo contador. Thread-unsafe —
        deve ser chamado apenas pela thread leitora da ClientConnection."""
        if self._dh_shared is None:
            raise RuntimeError("Canal não estabelecido.")
        nonce    = raw[:12]
        expected = (self._n_recv + 1).to_bytes(12, "big")
        if nonce != expected:
            raise ValueError("Contador de sequência inválido — possível replay.")
        self._n_recv += 1
        key       = crypto.hkdf_derive(self._dh_shared, f"c2s-msg-{self._n_recv}".encode())
        plaintext = crypto.decrypt_counter(key, raw)
        return Message.deserialize(plaintext.decode("utf-8"))

    # ── Transport ─────────────────────────────────────────────────────────────

    def send_raw(self, data: bytes) -> None:
        self._transport.send(data)

    def recv_raw(self) -> bytes:
        return self._transport.recv()

    def close(self) -> None:
        self._transport.close()

    # ── Propriedades ──────────────────────────────────────────────────────────

    @property
    def gx_bytes(self) -> bytes | None: return self._gx_bytes

    @property
    def gy_bytes(self) -> bytes | None: return self._gy_bytes
