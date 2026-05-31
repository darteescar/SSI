import json
import os
import sys
import base64

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

import common.crypto as crypto
import logging

_clog = logging.getLogger("keystore")
_DATA_DIR = os.path.join(_CLIENT_DIR, "data")


class Keystore:
    def __init__(self):
        self.udir: str | None = None
        self.cdir: str | None = None
        self.sdir: str | None = None
        self.hdir: str | None = None
        self.username: str | None = None
        self._storage_key: bytes | None = None

    def set_user(self, username: str):
        if not username:
            self.username = None
            self.udir = None
            self.cdir = None
            self.sdir = None
            self.hdir = None
            self._storage_key = None
            return

        self.username = username
        self.udir = os.path.join(_DATA_DIR, username)
        os.makedirs(self.udir, exist_ok=True)
        self.cdir = os.path.join(self.udir, "contacts")
        os.makedirs(self.cdir, exist_ok=True)
        self.sdir = os.path.join(self.udir, "sessions")
        os.makedirs(self.sdir, exist_ok=True)
        self.hdir = os.path.join(self.udir, "history")
        os.makedirs(self.hdir, exist_ok=True)

    def save_client_cert_and_key(self, cert_pem: str, privkey, password: str):
        if not self.udir: return
        with open(os.path.join(self.udir, "cert.crt"), "w") as f:
            f.write(cert_pem)
        crypto.encrypt_to_file(
            crypto.rsa_serialize_private(privkey),
            password,
            os.path.join(self.udir, "key.enc"),
        )

    def load_client_privkey(self, password: str):
        if not self.udir: return None
        privkey_pem = crypto.decrypt_from_file(
            os.path.join(self.udir, "key.enc"), password
        )
        privkey = crypto.rsa_load_private(privkey_pem)
        self._storage_key = crypto.hkdf_derive(
            privkey_pem,
            b"e2e-local-storage",
            salt=self.username.encode("utf-8"),
        )
        return privkey

    def load_own_cert_pem(self) -> str | None:
        if not self.udir: return None
        path = os.path.join(self.udir, "cert.crt")
        try:
            with open(path, "r") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def save_conversation_state(self, target: str, state) -> None:
        if not self.sdir or self._storage_key is None:
            return
        try:
            raw        = json.dumps(state.to_dict()).encode("utf-8")
            ciphertext = crypto.local_encrypt(self._storage_key, raw)
            with open(os.path.join(self.sdir, f"{target}.conv"), "wb") as f:
                f.write(ciphertext)
            _clog.debug(f"[E2E] estado de conversa com '{target}' persistido")
        except Exception as e:
            _clog.warning(f"[E2E] falha ao persistir estado com '{target}': {e}")

    def load_conversation_state(self, target: str):
        if not self.sdir or self._storage_key is None:
            return None
        path = os.path.join(self.sdir, f"{target}.conv")
        try:
            with open(path, "rb") as f:
                ciphertext = f.read()
            raw = crypto.local_decrypt(self._storage_key, ciphertext)
            from crypto.e2e_session import ConversationState
            return ConversationState.from_dict(json.loads(raw.decode("utf-8")))
        except (FileNotFoundError, ValueError):
            return None
        except Exception as e:
            _clog.warning(f"[E2E] falha ao carregar estado com '{target}': {e}")
            return None

    def delete_conversation_state(self, target: str) -> None:
        if not self.sdir: return
        path = os.path.join(self.sdir, f"{target}.conv")
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    def save_contact_cert(self, contact: str, cert_pem: str) -> None:
        if not self.cdir: return
        path = os.path.join(self.cdir, f"{contact}.crt")
        with open(path, "w") as f:
            f.write(cert_pem)
        _clog.debug(f"[CERT] certificado de '{contact}' guardado em '{path}'")

    def load_contact_cert_pem(self, contact: str) -> str | None:
        if not self.cdir: return None
        path = os.path.join(self.cdir, f"{contact}.crt")
        try:
            with open(path, "r") as f:
                return f.read()
        except FileNotFoundError:
            return None

    def save_prekeys(self, prekeys: dict, next_idx: int) -> None:
        if not self.sdir or self._storage_key is None:
            return
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PrivateFormat, NoEncryption
            )
            serializable = {"next_idx": next_idx, "keys": {}}
            for idx, (priv, pub) in prekeys.items():
                priv_der = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
                serializable["keys"][str(idx)] = {
                    "priv": base64.b64encode(priv_der).decode(),
                    "pub":  base64.b64encode(pub).decode(),
                }
            raw = json.dumps(serializable).encode("utf-8")
            ct  = crypto.local_encrypt(self._storage_key, raw)
            with open(os.path.join(self.sdir, "prekeys.dat"), "wb") as f:
                f.write(ct)
            _clog.info(f"prekeys persistidas: {len(prekeys)} chaves next_idx={next_idx} idx={sorted(prekeys.keys())}")
        except Exception as e:
            _clog.warning(f"falha ao persistir prekeys: {e}", exc_info=True)

    def load_prekeys(self) -> tuple[dict, int]:
        if not self.sdir or self._storage_key is None:
            return {}, 0
        path = os.path.join(self.sdir, "prekeys.dat")
        try:
            with open(path, "rb") as f:
                ct = f.read()
            raw  = crypto.local_decrypt(self._storage_key, ct)
            data = json.loads(raw.decode("utf-8"))
            from cryptography.hazmat.primitives.serialization import load_der_private_key
            result = {}
            for idx_str, entry in data["keys"].items():
                priv_der  = base64.b64decode(entry["priv"])
                pub_bytes = base64.b64decode(entry["pub"])
                priv_obj  = load_der_private_key(priv_der, password=None)
                result[int(idx_str)] = (priv_obj, pub_bytes)
            _clog.info(f"prekeys carregadas do disco: {len(result)} chaves next_idx={data.get('next_idx',0)} idx={sorted(result.keys())}")
            return result, data.get("next_idx", 0)
        except FileNotFoundError:
            _clog.debug("prekeys.dat não existe ainda")
            return {}, 0
        except ValueError as e:
            _clog.warning(f"erro a desencriptar prekeys.dat: {e}")
            return {}, 0
        except Exception as e:
            _clog.warning(f"falha ao carregar prekeys: {e}", exc_info=True)
            return {}, 0

    def save_group_sender_key(self, group_name: str, state) -> None:
        if not self.sdir or self._storage_key is None:
            return
        try:
            raw = json.dumps(state.to_dict()).encode("utf-8")
            ct  = crypto.local_encrypt(self._storage_key, raw)
            fname = f"gsk_{group_name}.dat"
            with open(os.path.join(self.sdir, fname), "wb") as f:
                f.write(ct)
            _clog.debug(f"[GroupSK] sender key de envio para '{group_name}' persistida")
        except Exception as e:
            _clog.warning(f"[GroupSK] falha ao persistir sender key de envio para '{group_name}': {e}")

    def load_group_sender_key(self, group_name: str):
        if not self.sdir or self._storage_key is None:
            return None
        path = os.path.join(self.sdir, f"gsk_{group_name}.dat")
        try:
            with open(path, "rb") as f:
                ct = f.read()
            raw = crypto.local_decrypt(self._storage_key, ct)
            from crypto.e2e_session import SenderKeyState
            return SenderKeyState.from_dict(json.loads(raw.decode("utf-8")))
        except FileNotFoundError:
            return None
        except Exception as e:
            _clog.warning(f"[GroupSK] falha ao carregar sender key de envio para '{group_name}': {e}")
            return None

    def save_group_recv_sender_key(self, group_name: str, member: str, state) -> None:
        if not self.sdir or self._storage_key is None:
            return
        try:
            path = os.path.join(self.sdir, f"gsk_recv_{group_name}.dat")
            existing = self._load_group_recv_raw(path) or {}
            existing[member] = state.to_dict()
            raw = json.dumps(existing).encode("utf-8")
            ct  = crypto.local_encrypt(self._storage_key, raw)
            with open(path, "wb") as f:
                f.write(ct)
            _clog.debug(f"[GroupSK] sender key de recepção de '{member}' para '{group_name}' persistida")
        except Exception as e:
            _clog.warning(f"[GroupSK] falha ao persistir sender key de recepção de '{member}': {e}")

    def load_group_recv_sender_keys(self, group_name: str) -> dict:
        if not self.sdir or self._storage_key is None:
            return {}
        path = os.path.join(self.sdir, f"gsk_recv_{group_name}.dat")
        raw_dict = self._load_group_recv_raw(path)
        if not raw_dict:
            return {}
        from crypto.e2e_session import SenderKeyState
        result = {}
        for member, d in raw_dict.items():
            try:
                result[member] = SenderKeyState.from_dict(d)
            except Exception as e:
                _clog.warning(f"[GroupSK] falha ao carregar sender key de '{member}': {e}")
        return result

    def delete_group_sender_keys(self, group_name: str) -> None:
        if not self.sdir:
            return
        for fname in [f"gsk_{group_name}.dat", f"gsk_recv_{group_name}.dat"]:
            path = os.path.join(self.sdir, fname)
            try:
                os.remove(path)
                _clog.debug(f"[GroupSK] ficheiro '{fname}' removido (rotação)")
            except FileNotFoundError:
                pass

    def _load_group_recv_raw(self, path: str) -> dict | None:
        try:
            with open(path, "rb") as f:
                ct = f.read()
            raw = crypto.local_decrypt(self._storage_key, ct)
            return json.loads(raw.decode("utf-8"))
        except FileNotFoundError:
            return None
        except Exception as e:
            _clog.warning(f"[GroupSK] falha ao ler ficheiro de recepção '{path}': {e}")
            return None

    def append_history(self, target: str, from_: str, to: str,
                       text: str, timestamp: str) -> None:
        if not self.hdir or self._storage_key is None:
            return
        history = self.load_history(target)
        history.append({"from_": from_, "to": to, "text": text, "timestamp": timestamp})
        try:
            raw = json.dumps(history).encode("utf-8")
            ct  = crypto.local_encrypt(self._storage_key, raw)
            with open(os.path.join(self.hdir, f"{target}.hist"), "wb") as f:
                f.write(ct)
        except Exception as e:
            _clog.warning(f"falha ao guardar histórico com '{target}': {e}")

    def load_history(self, target: str) -> list[dict]:
        if not self.hdir or self._storage_key is None:
            return []
        path = os.path.join(self.hdir, f"{target}.hist")
        try:
            with open(path, "rb") as f:
                ct = f.read()
            raw = crypto.local_decrypt(self._storage_key, ct)
            return json.loads(raw.decode("utf-8"))
        except FileNotFoundError:
            return []
        except ValueError as e:
            _clog.warning(f"falha ao decifrar histórico com '{target}': {e}")
            return []
        except Exception as e:
            _clog.warning(f"erro ao carregar histórico com '{target}': {e}")
            return []

    def delete_history(self, target: str) -> None:
        if not self.hdir:
            return
        path = os.path.join(self.hdir, f"{target}.hist")
        try:
            os.remove(path)
            _clog.info(f"histórico local com '{target}' apagado")
        except FileNotFoundError:
            pass
