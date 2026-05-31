import base64
from common.MsgType import MsgType

class AuthMessageMixin:
    # ── Auth ─────────────────────────────────────────────────────────────────

    @classmethod
    def req_login(cls, username: str, password: str):
        return cls(MsgType.LOGIN, {"username": username, "password": password})

    @classmethod
    def req_login_sts(cls, username: str, password: str, sig_bytes: bytes):
        """Primeira mensagem após DH: identifica o cliente com password e assinatura sobre g^x||g^y."""
        return cls(MsgType.LOGIN, {
            "username":  username,
            "password":  password,
            "signature": base64.b64encode(sig_bytes).decode("ascii"),
        })

    @classmethod
    def resp_login(cls, username: str, user_id: int = 0):
        return cls(MsgType.OK, {"username": username, "user_id": user_id, "info": f"Login bem-sucedido, bem-vindo {username}!"})

    @classmethod
    def req_registo(cls, username: str, password: str,
                    pubkey_pem: str, sig_bytes: bytes):
        return cls(MsgType.REGISTO, {
            "username":   username,
            "password":   password,
            "public_key": pubkey_pem,
            "signature":  base64.b64encode(sig_bytes).decode("ascii"),
        })

    @classmethod
    def resp_registo(cls, username: str, cert: str = "", user_id: int = 0):
        return cls(MsgType.OK, {
            "info":    f"Registo bem-sucedido, bem-vindo {username}!",
            "cert":    cert,
            "user_id": user_id,
        })

    @classmethod
    def req_logout(cls):
        return cls(MsgType.LOGOUT)

    @classmethod
    def resp_logout(cls):
        return cls(MsgType.OK, {"info": "Até logo!"})

    @classmethod
    def req_rekey(cls, gx_bytes: bytes):
        return cls(MsgType.REKEY, {"gx": base64.b64encode(gx_bytes).decode("ascii")})

    @classmethod
    def resp_rekey(cls, gy_bytes: bytes):
        return cls(MsgType.REKEY, {"gy": base64.b64encode(gy_bytes).decode("ascii")})

    # ── E2E prekeys ───────────────────────────────────────────────────────────

    @classmethod
    def req_prekey_upload(cls, prekeys: list[dict]):
        """prekeys: [{idx: int, pub: str_b64, sig: str_b64}, ...]
        pub = DER bytes do g^y_i em base64
        sig = RSA-PSS(client_privkey, g^y_i || idx.to_bytes(4,'big')) em base64
        """
        return cls(MsgType.PREKEY_UPLOAD, {"prekeys": prekeys})

    @classmethod
    def req_prekey_request(cls, username: str):
        """Pede uma prekey one-time + certificado do utilizador alvo."""
        return cls(MsgType.PREKEY_REQUEST, {"info": username})

    @classmethod
    def resp_prekey_bundle(cls, prekey_idx: int, prekey_pub: str,
                           prekey_sig: str, cert_pem: str, low_stock: bool = False):
        """Servidor → cliente: prekey one-time + certificado do alvo."""
        return cls(MsgType.PREKEY_BUNDLE, {
            "prekey_idx": prekey_idx,
            "prekey_pub": prekey_pub,
            "prekey_sig": prekey_sig,
            "cert_pem":   cert_pem,
            "low_stock":  low_stock,
        })

    @classmethod
    def resp_online_bundle(cls, cert_pem: str):
        """Servidor → cliente: B está online, usa DH direto (sem consumir prekey)."""
        return cls(MsgType.ONLINE_BUNDLE, {"cert_pem": cert_pem})

    @classmethod
    def req_cert_request(cls, username: str):
        """Pede apenas o certificado de um utilizador (sem consumir prekey)."""
        return cls(MsgType.CERT_REQUEST, {"info": username})

    @classmethod
    def resp_cert(cls, username: str, cert_pem: str):
        return cls(MsgType.OK, {"info": username, "cert_pem": cert_pem})

    # ── E2E relay ─────────────────────────────────────────────────────────────

    @classmethod
    def req_e2e_msg(cls, to: str, msg_id: str, payload_b64: str):
        """Cliente → servidor: blob E2E opaco para relay.
        payload_b64 = base64 do payload cifrado completo."""
        return cls(MsgType.E2E_MSG, {
            "to":      to,
            "msg_id":  msg_id,
            "payload": payload_b64,
        })

    @classmethod
    def push_e2e_deliver(cls, from_: str, msg_id: str, payload_b64: str):
        """Servidor → cliente: entrega de blob E2E (push ou fila offline)."""
        return cls(MsgType.E2E_DELIVER, {
            "from_":   from_,
            "msg_id":  msg_id,
            "payload": payload_b64,
        })

    @classmethod
    def req_e2e_ack(cls, msg_id: str):
        """Cliente → servidor: confirma recepção de msg_id."""
        return cls(MsgType.E2E_ACK, {"msg_id": msg_id})
