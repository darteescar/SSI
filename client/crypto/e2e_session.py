"""E2E session manager — X3DH-like initiation + symmetric ratchet.

Protocol summary
----------------
Initiation (A → B):
  1. A fetches B's one-time prekey bundle (idx, g^y_i, sig_i, cert_B)
  2. A verifies cert_B (CA-signed), verifies sig_i, verifies stored TOFU cert
  3. A generates ephemeral keypair (x, g^x)
  4. shared_secret = DH(x, g^y_i)
  5. root_key       = HKDF(shared_secret, info="conv-init")
     A signs (g^x || idx.to_bytes(4,'big')) with its identity key → sig_x
  6. A sends E2E_MSG with payload = {type:"init", gx, prekey_idx, sig_x, cert_A}
  7. chain_key_send = HKDF(root_key, info="send")
     chain_key_recv = HKDF(root_key, info="recv")
     (B derives mirrored keys)

Reception/response (B receives init payload):
  1. B verifies cert_A, verifies sig_x over (g^x || idx.to_bytes(4,'big'))
  2. B retrieves its prekey private key for the given idx
  3. Same DH → same root_key → chain_key_recv / chain_key_send (mirrored)

Ratchet (per message):
  msg_key       = HMAC(chain_key, "message")
  new_chain_key = HMAC(chain_key, "chain")
  nonce         = counter.to_bytes(12, 'big')
  ciphertext    = AES-256-GCM(msg_key, nonce, plaintext, aad=counter.to_bytes(8,'big'))
  Autenticidade garantida pelo tag GCM — sem assinatura RSA por mensagem.

Out-of-order: skipped keys cached up to MAX_SKIP.
Replay: strictly increasing counter enforced.
"""

import base64
import json
import logging
import os
import uuid

import common.crypto as crypto
from common.Message import Message

_clog = logging.getLogger("e2e")

N_PREKEYS = 25
MAX_SKIP  = 1000


def _ratchet_advance(chain_key: bytes) -> tuple[bytes, bytes]:
    msg_key       = crypto.hmac_derive(chain_key, "message")
    new_chain_key = crypto.hmac_derive(chain_key, "chain")
    return msg_key, new_chain_key


def _aes_encrypt(msg_key: bytes, plaintext: bytes, counter: int) -> bytes:
    nonce = counter.to_bytes(12, "big")
    aad   = counter.to_bytes(8, "big")
    return crypto.encrypt_counter(msg_key, nonce, plaintext, aad)


def _aes_decrypt(msg_key: bytes, data: bytes, counter: int) -> bytes:
    aad = counter.to_bytes(8, "big")
    return crypto.decrypt_counter(msg_key, data, aad)


class ConversationState:
    __slots__ = (
        "chain_key_send", "chain_key_recv",
        "counter_send",   "counter_recv",
        "skipped_keys",
    )

    def __init__(self, chain_key_send: bytes, chain_key_recv: bytes):
        self.chain_key_send = chain_key_send
        self.chain_key_recv = chain_key_recv
        self.counter_send   = 0
        self.counter_recv   = 0
        self.skipped_keys: dict[int, bytes] = {}

    def to_dict(self) -> dict:
        return {
            "chain_key_send": base64.b64encode(self.chain_key_send).decode(),
            "chain_key_recv": base64.b64encode(self.chain_key_recv).decode(),
            "counter_send":   self.counter_send,
            "counter_recv":   self.counter_recv,
            "skipped_keys":   {
                str(k): base64.b64encode(v).decode()
                for k, v in self.skipped_keys.items()
            },
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ConversationState":
        obj = cls.__new__(cls)
        obj.chain_key_send = base64.b64decode(d["chain_key_send"])
        obj.chain_key_recv = base64.b64decode(d["chain_key_recv"])
        obj.counter_send   = d["counter_send"]
        obj.counter_recv   = d["counter_recv"]
        obj.skipped_keys   = {
            int(k): base64.b64decode(v)
            for k, v in d.get("skipped_keys", {}).items()
        }
        return obj


class E2EManager:
    def __init__(self, keystore, server_cert_path: str):
        self.keystore         = keystore
        self.server_cert_path = server_cert_path

        self.client_privkey = None

        self._prekeys: dict[int, tuple] = {}
        self._next_prekey_idx: int      = 0

        self._sessions: dict[str, ConversationState] = {}
        self._prekeys_loaded: bool = False

        self._pending_dh: dict[str, object] = {}

    def reset(self):
        self.client_privkey = None
        self._prekeys.clear()
        self._sessions.clear()
        self._pending_dh.clear()
        self._prekeys_loaded = False

    def set_privkey(self, privkey):
        self.client_privkey = privkey

    def _ensure_prekeys_loaded(self):
        if not self._prekeys_loaded:
            loaded, next_idx = self.keystore.load_prekeys()
            if loaded:
                self._prekeys.update(loaded)
                self._next_prekey_idx = max(next_idx, self._next_prekey_idx)
            self._prekeys_loaded = True

    def generate_prekeys_payload(self) -> list[dict]:
        self._ensure_prekeys_loaded()
        payload = []
        for _ in range(N_PREKEYS):
            idx               = self._next_prekey_idx
            self._next_prekey_idx += 1
            priv, pub_bytes   = crypto.dh_generate_keypair()
            self._prekeys[idx] = (priv, pub_bytes)
            sig = crypto.rsa_sign(
                self.client_privkey,
                pub_bytes + idx.to_bytes(4, "big"),
            )
            payload.append({
                "idx": idx,
                "pub": base64.b64encode(pub_bytes).decode("ascii"),
                "sig": base64.b64encode(sig).decode("ascii"),
            })
        self.keystore.save_prekeys(self._prekeys, self._next_prekey_idx)
        _clog.info(f"geradas {len(payload)} prekeys DH (idx {payload[0]['idx']}..{payload[-1]['idx']}), cada uma assinada com a chave de identidade RSA — serão usadas por outros utilizadores para iniciar sessão E2E enquanto este estiver offline")
        return payload

    def has_session(self, target: str) -> bool:
        if target in self._sessions:
            return True
        state = self.keystore.load_conversation_state(target)
        if state is not None:
            self._sessions[target] = state
            return True
        return False

    def initiate_online(self, target: str, cert_pem_str: str) -> str | None:
        try:
            server_ca   = crypto.cert_load(self.server_cert_path)
            target_cert = crypto.cert_load_bytes(cert_pem_str.encode("ascii"))
            crypto.cert_verify(target_cert, server_ca)

            stored_cert = self.keystore.load_contact_cert_pem(target)
            if stored_cert is not None:
                if stored_cert.strip() != cert_pem_str.strip():
                    raise ValueError(f"Certificado de '{target}' mudou — possível MITM.")
            else:
                self.keystore.save_contact_cert(target, cert_pem_str)

            x_priv, gx_bytes = crypto.dh_generate_keypair()
            sig_gx = crypto.rsa_sign(self.client_privkey, gx_bytes)
            own_cert_pem = self.keystore.load_own_cert_pem() or ""

            self._pending_dh[target] = x_priv

            payload = {
                "type":  "dh_init",
                "gx":    base64.b64encode(gx_bytes).decode("ascii"),
                "sig":   base64.b64encode(sig_gx).decode("ascii"),
                "cert":  own_cert_pem,
            }
            payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode("ascii")
            _clog.info(f"E2E par-a-par com '{target}' (online): enviado dh_init com g^x assinado pela chave de identidade RSA e certificado X.509 próprio — a aguardar dh_resp de '{target}'")
            return payload_b64
        except Exception as e:
            _clog.error(f"E2E par-a-par com '{target}' (online): falha a montar dh_init — {e}")
            return None

    def receive_dh_resp(self, sender: str, payload_b64: str) -> bool:
        try:
            raw     = base64.b64decode(payload_b64)
            p       = json.loads(raw.decode("utf-8"))
            if p.get("type") != "dh_resp":
                return False

            gy_bytes     = base64.b64decode(p["gy"])
            sig_gy       = base64.b64decode(p["sig"])
            cert_pem_str = p.get("cert", "")

            server_ca   = crypto.cert_load(self.server_cert_path)
            sender_cert = crypto.cert_load_bytes(cert_pem_str.encode("ascii"))
            crypto.cert_verify(sender_cert, server_ca)

            stored_cert = self.keystore.load_contact_cert_pem(sender)
            if stored_cert is not None:
                if stored_cert.strip() != cert_pem_str.strip():
                    raise ValueError(f"Certificado de '{sender}' mudou — possível MITM.")
            else:
                self.keystore.save_contact_cert(sender, cert_pem_str)

            sender_pubkey = crypto.cert_get_public_key(sender_cert)
            crypto.rsa_verify(sender_pubkey, sig_gy, gy_bytes)

            x_priv = self._pending_dh.pop(sender, None)
            if x_priv is None:
                raise ValueError(f"Sem x_priv pendente para '{sender}'.")

            shared   = crypto.dh_compute_shared(x_priv, gy_bytes)
            root_key = crypto.hkdf_derive(shared, b"conv-init-online")
            chain_key_send = crypto.hkdf_derive(root_key, b"send")
            chain_key_recv = crypto.hkdf_derive(root_key, b"recv")

            state = ConversationState(chain_key_send, chain_key_recv)
            self._sessions[sender] = state
            self.keystore.save_conversation_state(sender, state)
            _clog.info(f"E2E par-a-par com '{sender}' (online): dh_resp recebido e g^y verificado contra o certificado de '{sender}'. Sessão estabelecida — chain_keys derivadas via HKDF do segredo DH partilhado, mensagens seguintes via AES-256-GCM + ratchet simétrico HMAC-SHA256")
            return True
        except Exception as e:
            _clog.error(f"E2E par-a-par com '{sender}' (online): falha a processar dh_resp — {e}")
            return False

    def receive_dh_init(self, sender: str, payload_b64: str) -> str | None:
        try:
            raw = base64.b64decode(payload_b64)
            p   = json.loads(raw.decode("utf-8"))
            if p.get("type") != "dh_init":
                return None

            gx_bytes     = base64.b64decode(p["gx"])
            sig_gx       = base64.b64decode(p["sig"])
            cert_pem_str = p.get("cert", "")

            server_ca   = crypto.cert_load(self.server_cert_path)
            sender_cert = crypto.cert_load_bytes(cert_pem_str.encode("ascii"))
            crypto.cert_verify(sender_cert, server_ca)

            stored_cert = self.keystore.load_contact_cert_pem(sender)
            if stored_cert is not None:
                if stored_cert.strip() != cert_pem_str.strip():
                    raise ValueError(f"Certificado de '{sender}' mudou — possível MITM.")
            else:
                self.keystore.save_contact_cert(sender, cert_pem_str)

            sender_pubkey = crypto.cert_get_public_key(sender_cert)
            crypto.rsa_verify(sender_pubkey, sig_gx, gx_bytes)

            y_priv, gy_bytes = crypto.dh_generate_keypair()
            sig_gy = crypto.rsa_sign(self.client_privkey, gy_bytes)
            own_cert_pem = self.keystore.load_own_cert_pem() or ""

            shared   = crypto.dh_compute_shared(y_priv, gx_bytes)
            root_key = crypto.hkdf_derive(shared, b"conv-init-online")
            chain_key_send = crypto.hkdf_derive(root_key, b"recv")
            chain_key_recv = crypto.hkdf_derive(root_key, b"send")

            state = ConversationState(chain_key_send, chain_key_recv)
            self._sessions[sender] = state
            self.keystore.save_conversation_state(sender, state)
            _clog.info(f"E2E par-a-par com '{sender}' (online): dh_init recebido e g^x verificado contra o certificado de '{sender}'. Sessão estabelecida — a responder com dh_resp contendo g^y assinado")

            resp_payload = {
                "type": "dh_resp",
                "gy":   base64.b64encode(gy_bytes).decode("ascii"),
                "sig":  base64.b64encode(sig_gy).decode("ascii"),
                "cert": own_cert_pem,
            }
            return base64.b64encode(json.dumps(resp_payload).encode()).decode("ascii")
        except Exception as e:
            _clog.error(f"E2E par-a-par com '{sender}' (online): falha a processar dh_init — {e}")
            return None

    def initiate(self, target: str, bundle: Message) -> str | None:
        try:
            server_ca        = crypto.cert_load(self.server_cert_path)
            prekey_idx       = bundle.prekey_idx
            prekey_pub_bytes = base64.b64decode(bundle.prekey_pub)
            prekey_sig_bytes = base64.b64decode(bundle.prekey_sig)
            cert_pem_str     = bundle.cert_pem

            target_cert = crypto.cert_load_bytes(cert_pem_str.encode("ascii"))
            crypto.cert_verify(target_cert, server_ca)

            stored_cert_pem = self.keystore.load_contact_cert_pem(target)
            if stored_cert_pem is not None:
                if stored_cert_pem.strip() != cert_pem_str.strip():
                    raise ValueError(f"Certificado de '{target}' mudou — possível MITM.")
            else:
                self.keystore.save_contact_cert(target, cert_pem_str)

            target_pubkey = crypto.cert_get_public_key(target_cert)

            crypto.rsa_verify(
                target_pubkey, prekey_sig_bytes,
                prekey_pub_bytes + prekey_idx.to_bytes(4, "big"),
            )

            x_priv, gx_bytes = crypto.dh_generate_keypair()

            shared   = crypto.dh_compute_shared(x_priv, prekey_pub_bytes)
            root_key = crypto.hkdf_derive(shared, b"conv-init")

            sig_gx = crypto.rsa_sign(
                self.client_privkey,
                gx_bytes + prekey_idx.to_bytes(4, "big"),
            )

            own_cert_pem = self.keystore.load_own_cert_pem() or ""

            init_payload = {
                "type":       "init",
                "gx":         base64.b64encode(gx_bytes).decode("ascii"),
                "prekey_idx": prekey_idx,
                "sig_gx":     base64.b64encode(sig_gx).decode("ascii"),
                "cert":       own_cert_pem,
            }
            payload_b64 = base64.b64encode(
                json.dumps(init_payload).encode("utf-8")
            ).decode("ascii")

            chain_key_send = crypto.hkdf_derive(root_key, b"send")
            chain_key_recv = crypto.hkdf_derive(root_key, b"recv")

            state = ConversationState(chain_key_send, chain_key_recv)
            self._sessions[target] = state
            self.keystore.save_conversation_state(target, state)
            _clog.info(f"E2E par-a-par com '{target}' (offline, X3DH): prekey idx={prekey_idx} consumida e verificada com a chave de identidade RSA de '{target}'. Segredo DH derivado, chain_keys instaladas — sessão pronta para enviar mensagens com AES-256-GCM + ratchet HMAC-SHA256, mesmo antes de '{target}' processar o init")

            return payload_b64

        except Exception as e:
            _clog.error(f"E2E par-a-par com '{target}' (offline, X3DH): falha no initiate — {e}")
            return None

    def receive_init(self, sender: str, payload_b64: str) -> bool:
        try:
            raw          = base64.b64decode(payload_b64)
            init_payload = json.loads(raw.decode("utf-8"))

            if init_payload.get("type") != "init":
                return False

            gx_bytes  = base64.b64decode(init_payload["gx"])
            prekey_idx = int(init_payload["prekey_idx"])
            sig_gx    = base64.b64decode(init_payload["sig_gx"])
            cert_pem_str = init_payload.get("cert", "")

            server_ca = crypto.cert_load(self.server_cert_path)
            sender_cert = crypto.cert_load_bytes(cert_pem_str.encode("ascii"))
            crypto.cert_verify(sender_cert, server_ca)

            stored_cert = self.keystore.load_contact_cert_pem(sender)
            if stored_cert is not None:
                if stored_cert.strip() != cert_pem_str.strip():
                    raise ValueError(f"Certificado de '{sender}' mudou — possível MITM.")
            else:
                self.keystore.save_contact_cert(sender, cert_pem_str)

            sender_pubkey = crypto.cert_get_public_key(sender_cert)

            crypto.rsa_verify(
                sender_pubkey, sig_gx,
                gx_bytes + prekey_idx.to_bytes(4, "big"),
            )

            self._ensure_prekeys_loaded()
            prekey_entry = self._prekeys.get(prekey_idx)
            if prekey_entry is None:
                _clog.error(f"E2E par-a-par com '{sender}' (offline, X3DH): prekey idx={prekey_idx} indicada no init não existe no nosso stock local — possível replay ou estado dessincronizado")
                return False
            our_priv, our_pub = prekey_entry

            shared   = crypto.dh_compute_shared(our_priv, gx_bytes)
            root_key = crypto.hkdf_derive(shared, b"conv-init")

            chain_key_send = crypto.hkdf_derive(root_key, b"recv")
            chain_key_recv = crypto.hkdf_derive(root_key, b"send")

            state = ConversationState(chain_key_send, chain_key_recv)
            self._sessions[sender] = state
            self.keystore.save_conversation_state(sender, state)
            _clog.info(f"E2E par-a-par com '{sender}' (offline, X3DH): init verificado — prekey idx={prekey_idx} consumida, segredo DH derivado, chain_keys instaladas espelhando as de '{sender}'. Sessão pronta")
            return True

        except Exception as e:
            _clog.error(f"E2E par-a-par com '{sender}' (offline, X3DH): falha no receive_init — {e}")
            return False

    def send_message(self, target: str, plaintext: str) -> str | None:
        state = self._sessions.get(target)
        if state is None:
            _clog.error(f"send_message('{target}'): sem sessão activa")
            return None
        try:
            msg_key, state.chain_key_send = _ratchet_advance(state.chain_key_send)
            counter = state.counter_send
            state.counter_send += 1

            ct_with_nonce = _aes_encrypt(msg_key, plaintext.encode("utf-8"), counter)

            msg_payload = {
                "type":    "msg",
                "counter": counter,
                "ct":      base64.b64encode(ct_with_nonce).decode("ascii"),
            }
            self.keystore.save_conversation_state(target, state)
            payload_b64 = base64.b64encode(json.dumps(msg_payload).encode("utf-8")).decode("ascii")
            ct_b64_preview = base64.b64encode(ct_with_nonce).decode("ascii")[:32]
            _clog.info(
                f"cifrada mensagem par-a-par para '{target}' (counter={counter}): "
                f"msg_key derivada do ratchet AES-256-GCM, plaintext=\"{plaintext}\" → "
                f"ciphertext {len(ct_with_nonce)}B ({ct_b64_preview}...). Chain_key avançada"
            )
            return payload_b64

        except Exception as e:
            _clog.error(f"falha a cifrar mensagem par-a-par para '{target}': {e}")
            return None

    def receive_message(self, sender: str, payload_b64: str) -> str | None:
        state = self._sessions.get(sender)
        if state is None:
            _clog.error(f"receive_message('{sender}'): sem sessão activa")
            return None
        try:
            raw     = base64.b64decode(payload_b64)
            p       = json.loads(raw.decode("utf-8"))
            counter = int(p["counter"])
            ct      = base64.b64decode(p["ct"])
            _clog.debug(f"receive_message('{sender}'): counter={counter} ct={len(ct)}B counter_recv_esperado={state.counter_recv}")

            if counter in state.skipped_keys:
                msg_key = state.skipped_keys.pop(counter)
                self.keystore.save_conversation_state(sender, state)
            elif counter >= state.counter_recv:
                if counter - state.counter_recv > MAX_SKIP:
                    raise ValueError("Demasiadas mensagens em falta — possível ataque.")
                while state.counter_recv < counter:
                    sk, state.chain_key_recv = _ratchet_advance(state.chain_key_recv)
                    state.skipped_keys[state.counter_recv] = sk
                    state.counter_recv += 1
                msg_key, state.chain_key_recv = _ratchet_advance(state.chain_key_recv)
                state.counter_recv += 1
                self.keystore.save_conversation_state(sender, state)
            else:
                raise ValueError(f"Replay detectado: counter={counter} < esperado={state.counter_recv}")

            plaintext = _aes_decrypt(msg_key, ct, counter)
            ct_b64_preview = base64.b64encode(ct).decode("ascii")[:32]
            _clog.info(
                f"decifrada mensagem par-a-par de '{sender}' (counter={counter}): "
                f"ciphertext {len(ct)}B ({ct_b64_preview}...) → plaintext=\"{plaintext.decode()}\". "
                f"Tag GCM válido (autenticidade confirmada), chain_key avançada"
            )
            return plaintext.decode("utf-8")

        except Exception as e:
            _clog.error(f"falha a decifrar mensagem par-a-par de '{sender}': {e}")
            return None

    @staticmethod
    def new_msg_id() -> str:
        return str(uuid.uuid4())


class SenderKeyState:
    __slots__ = ("chain_key", "counter", "sig_priv", "sig_pub_bytes", "skipped_keys")

    def __init__(self, chain_key: bytes, sig_priv, sig_pub_bytes: bytes):
        self.chain_key    = chain_key
        self.counter      = 0
        self.sig_priv     = sig_priv
        self.sig_pub_bytes = sig_pub_bytes
        self.skipped_keys: dict[int, bytes] = {}

    def to_dict(self) -> dict:
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PrivateFormat, NoEncryption,
        )
        d: dict = {
            "chain_key":     base64.b64encode(self.chain_key).decode(),
            "counter":       self.counter,
            "sig_pub_bytes": base64.b64encode(self.sig_pub_bytes).decode(),
            "skipped_keys":  {
                str(k): base64.b64encode(v).decode()
                for k, v in self.skipped_keys.items()
            },
        }
        if self.sig_priv is not None:
            priv_der = self.sig_priv.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )
            d["sig_priv"] = base64.b64encode(priv_der).decode()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SenderKeyState":
        from cryptography.hazmat.primitives.serialization import load_der_private_key
        chain_key    = base64.b64decode(d["chain_key"])
        sig_pub_bytes = base64.b64decode(d["sig_pub_bytes"])
        sig_priv     = None
        if "sig_priv" in d:
            sig_priv = load_der_private_key(base64.b64decode(d["sig_priv"]), password=None)
        obj = cls.__new__(cls)
        obj.chain_key     = chain_key
        obj.counter       = d["counter"]
        obj.sig_priv      = sig_priv
        obj.sig_pub_bytes = sig_pub_bytes
        obj.skipped_keys  = {
            int(k): base64.b64decode(v)
            for k, v in d.get("skipped_keys", {}).items()
        }
        return obj


class GroupSenderKeyManager:
    def __init__(self, keystore):
        self.keystore = keystore
        self._my_sk: dict[str, SenderKeyState] = {}
        self._recv_sk: dict[str, dict[str, SenderKeyState]] = {}

    def reset(self):
        self._my_sk.clear()
        self._recv_sk.clear()

    def generate_sender_key(self, group_name: str) -> SenderKeyState:
        chain_key_initial = os.urandom(32)
        sig_rsa_priv = crypto.rsa_generate_keypair()
        sig_pub_pem  = crypto.rsa_serialize_public(sig_rsa_priv)
        state = SenderKeyState(chain_key_initial, sig_rsa_priv, sig_pub_pem)
        self._my_sk[group_name] = state
        self.keystore.save_group_sender_key(group_name, state)
        _clog.info(f"sender key própria gerada para o grupo '{group_name}': chain_key aleatória de 256b + par RSA dedicado para assinatura de mensagens (separado da chave de identidade). Próximo passo: distribuir esta SK a cada membro via E2E par-a-par")
        return state

    def get_my_sender_key(self, group_name: str) -> SenderKeyState | None:
        if group_name in self._my_sk:
            return self._my_sk[group_name]
        state = self.keystore.load_group_sender_key(group_name)
        if state:
            self._my_sk[group_name] = state
        return state

    def has_sender_key(self, group_name: str) -> bool:
        return self.get_my_sender_key(group_name) is not None

    def build_sk_dist_payload(self, group_name: str) -> str | None:
        state = self.get_my_sender_key(group_name)
        if state is None:
            return None
        payload = {
            "type":      "sk_dist",
            "group":     group_name,
            "chain_key": base64.b64encode(state.chain_key).decode(),
            "sig_pub":   base64.b64encode(state.sig_pub_bytes).decode(),
            "counter":   state.counter,
        }
        _clog.info(f"preparado payload sk_dist da minha sender key do grupo '{group_name}' no estado actual (counter={state.counter}) — será cifrado no canal E2E par-a-par antes de ser enviado")
        return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    def receive_sk_dist(self, sender: str, payload_b64: str) -> str | None:
        try:
            raw = base64.b64decode(payload_b64)
            p   = json.loads(raw.decode("utf-8"))
            if p.get("type") != "sk_dist":
                return None

            group_name    = p["group"]
            chain_key     = base64.b64decode(p["chain_key"])
            sig_pub_bytes = base64.b64decode(p["sig_pub"])
            counter       = int(p["counter"])

            state = SenderKeyState(chain_key, None, sig_pub_bytes)
            state.counter = counter
            self._recv_sk.setdefault(group_name, {})[sender] = state
            self.keystore.save_group_recv_sender_key(group_name, sender, state)
            _clog.info(f"recebida sender key de '{sender}' para o grupo '{group_name}' (counter inicial={counter}) — origem autenticada pelo canal E2E par-a-par (tag GCM válido). Posso agora decifrar mensagens de grupo provenientes de '{sender}'")
            return group_name
        except Exception as e:
            _clog.error(f"falha a processar sender key recebida de '{sender}': {e}")
            return None

    def discard_sender_key(self, group_name: str) -> None:
        self._my_sk.pop(group_name, None)
        self._recv_sk.pop(group_name, None)
        self.keystore.delete_group_sender_keys(group_name)
        _clog.info(f"[GRUPO CHAVE] sender keys de '{group_name}' descartadas (rotação após saída de membro)")

    def encrypt_group_message(self, group_name: str, plaintext: str) -> str | None:
        state = self.get_my_sender_key(group_name)
        if state is None:
            _clog.error(f"[GroupSK] sem sender key para grupo '{group_name}'")
            return None
        try:
            msg_key, state.chain_key = _ratchet_advance(state.chain_key)
            counter = state.counter
            state.counter += 1

            ct_with_nonce = _aes_encrypt(msg_key, plaintext.encode("utf-8"), counter)

            sig_data = ct_with_nonce + counter.to_bytes(8, "big") + group_name.encode("utf-8")
            sig      = crypto.rsa_sign(state.sig_priv, sig_data)

            msg_payload = {
                "counter": counter,
                "ct":      base64.b64encode(ct_with_nonce).decode("ascii"),
                "sig":     base64.b64encode(sig).decode("ascii"),
            }
            self.keystore.save_group_sender_key(group_name, state)
            ct_b64_preview = base64.b64encode(ct_with_nonce).decode("ascii")[:32]
            _clog.info(
                f"[CIFRA GRUPO] → '{group_name}' | plaintext: \"{plaintext}\" | "
                f"cifra: AES-256-GCM + RSA-PSS (sender key) | "
                f"ciphertext ({len(ct_with_nonce)}B): {ct_b64_preview}..."
            )
            return base64.b64encode(json.dumps(msg_payload).encode("utf-8")).decode("ascii")
        except Exception as e:
            _clog.error(f"[CIFRA GRUPO] → '{group_name}': falha — {e}")
            return None

    def decrypt_group_message(self, group_name: str, sender: str, payload_b64: str) -> str | None:
        recv_states = self._recv_sk.get(group_name)
        if recv_states is None:
            recv_states = self.keystore.load_group_recv_sender_keys(group_name)
            if recv_states:
                self._recv_sk[group_name] = recv_states
        state = (recv_states or {}).get(sender)
        if state is None:
            _clog.error(f"[GroupSK] sem sender key de recepção de '{sender}' para grupo '{group_name}'")
            return None
        try:
            raw     = base64.b64decode(payload_b64)
            p       = json.loads(raw.decode("utf-8"))
            counter = int(p["counter"])
            ct      = base64.b64decode(p["ct"])
            sig     = base64.b64decode(p["sig"])

            # Verificar assinatura ANTES de qualquer avanço do ratchet
            sig_data   = ct + counter.to_bytes(8, "big") + group_name.encode("utf-8")
            sender_pub = crypto.rsa_load_public_from_bytes(state.sig_pub_bytes)
            crypto.rsa_verify(sender_pub, sig, sig_data)

            if counter in state.skipped_keys:
                msg_key = state.skipped_keys.pop(counter)
            elif counter >= state.counter:
                if counter - state.counter > MAX_SKIP:
                    raise ValueError("Demasiadas mensagens em falta.")
                while state.counter < counter:
                    sk, state.chain_key = _ratchet_advance(state.chain_key)
                    state.skipped_keys[state.counter] = sk
                    state.counter += 1
                msg_key, state.chain_key = _ratchet_advance(state.chain_key)
                state.counter += 1
            else:
                raise ValueError(f"Replay detectado: counter={counter} < esperado={state.counter}")

            plaintext = _aes_decrypt(msg_key, ct, counter)
            self.keystore.save_group_recv_sender_key(group_name, sender, state)
            ct_b64_preview = base64.b64encode(ct).decode("ascii")[:32]
            _clog.info(
                f"[DECIFRA GRUPO] ← '{sender}' em '{group_name}' | "
                f"cifra: AES-256-GCM + RSA-PSS (sender key) | "
                f"ciphertext ({len(ct)}B): {ct_b64_preview}... | "
                f"plaintext: \"{plaintext.decode()}\""
            )
            return plaintext.decode("utf-8")
        except Exception as e:
            _clog.error(f"[DECIFRA GRUPO] ← '{sender}' em '{group_name}': falha — {e}")
            return None

    def has_recv_key(self, group_name: str, sender: str) -> bool:
        recv = self._recv_sk.get(group_name, {})
        if sender in recv:
            return True
        disk_states = self.keystore.load_group_recv_sender_keys(group_name)
        if disk_states and sender in disk_states:
            self._recv_sk.setdefault(group_name, {})[sender] = disk_states[sender]
            return True
        return False
