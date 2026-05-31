import base64
import os
import sys
import queue
import threading
import logging
from typing import Callable

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

import common.crypto as crypto
from common.Message import Message
from common.MsgType import MsgType
from common.transport import Transport

from net.secure_channel import SecureChannel
from crypto.keystore import Keystore
from crypto.e2e_session import E2EManager, GroupSenderKeyManager, N_PREKEYS

_LOG_PATH = os.path.join(_CLIENT_DIR, "e2e.log")
_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)-5s] %(name)-9s user=%(user)-10s — %(message)s",
    datefmt="%H:%M:%S",
)

_current_user_holder = {"user": "-"}


def set_logger_user(username: str | None) -> None:
    _current_user_holder["user"] = username or "-"


class _UserFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.user = _current_user_holder["user"]
        return True


_user_filter = _UserFilter()


def _setup_logger(name: str) -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        lg.setLevel(logging.DEBUG)
        fh = logging.FileHandler(_LOG_PATH, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(_fmt)
        fh.addFilter(_user_filter)
        lg.addHandler(fh)
    return lg

_clog        = _setup_logger("network")
_setup_logger("e2e")
_setup_logger("keystore")


HOST = "127.0.0.1"
PORT = 6767

_DATA_DIR = os.path.join(_CLIENT_DIR, "data")
SERVER_CERT_PATH = os.path.join(_DATA_DIR, "ca", "server.crt")


class NetworkClient:
    def __init__(self):
        self.transport = Transport(HOST, PORT)
        self.channel   = SecureChannel(self.transport, SERVER_CERT_PATH)
        self.keystore  = Keystore()
        self.e2e       = E2EManager(self.keystore, SERVER_CERT_PATH)
        self.group_sk  = GroupSenderKeyManager(self.keystore)

        self.queue: queue.Queue[Message] = queue.Queue()
        self.receive_thread: threading.Thread | None = None
        self.on_message_callback: Callable[[Message], None] | None = None
        self._async_msg_ids: set[str] = set()
        self._async_ids_lock: threading.Lock = threading.Lock()

        self.username: str | None = None
        self.user_id: int | None  = None

    def connect(self) -> None:
        self.transport.connect()
        self.queue = queue.Queue()
        self.channel.dh_handshake()

    def disconnect(self) -> None:
        self.channel.disconnect()
        self.keystore.set_user("")
        self.e2e.reset()
        self.group_sk.reset()
        self.username = None
        self.user_id  = None
        set_logger_user(None)

    def is_logged_in(self) -> bool:
        return self.channel.dh_shared is not None and self.username is not None

    def set_logged_out(self) -> None:
        self.username = None
        self.user_id  = None
        self.keystore.set_user("")
        self.e2e.reset()
        self.group_sk.reset()
        set_logger_user(None)

    # ── Autenticação ──────────────────────────────────────────────────────────

    def registo(self, username: str, password: str) -> Message:
        if self.channel.dh_shared is None or self.channel.gx_bytes is None:
            raise RuntimeError("Sem canal seguro — chama connect() primeiro.")

        client_privkey = crypto.rsa_generate_keypair()
        pubkey_pem     = crypto.rsa_serialize_public(client_privkey)
        _clog.info(f"registo de '{username}': par RSA-2048 gerado localmente (pub={len(pubkey_pem)}B)")

        sig_bytes = crypto.rsa_sign(
            client_privkey,
            self.channel.gx_bytes + self.channel.gy_bytes + pubkey_pem,
        )
        _clog.info(f"registo de '{username}': assinatura PoP (Sign_priv(g^x||g^y||pubkey)={len(sig_bytes)}B) — prova que conhece a chave privada associada à pubkey")

        req = Message.req_registo(username, password,
                                  pubkey_pem.decode("utf-8"), sig_bytes)
        self.channel.send_encrypted(req.serialize().encode("utf-8"))

        response = self.channel.recv_encrypted_blocking()
        if response.type == MsgType.OK:
            self.keystore.set_user(username)
            self.keystore.save_client_cert_and_key(response.get("cert"), client_privkey, password)
            self.keystore.set_user("")

        return response

    def login(self, username: str, password: str) -> Message:
        if self.channel.dh_shared is None or self.channel.gx_bytes is None:
            raise RuntimeError("Sem canal seguro — chama connect() primeiro.")

        self.keystore.set_user(username)
        try:
            client_privkey = self.keystore.load_client_privkey(password)
        except ValueError:
            self.keystore.set_user("")
            return Message.error("Password incorreta.")
        if not client_privkey:
            self.keystore.set_user("")
            return Message.error("Username ou password inválidos.")

        sig_cliente = crypto.rsa_sign(
            client_privkey,
            self.channel.gx_bytes + self.channel.gy_bytes,
        )
        self.channel.send_encrypted(
            Message.req_login_sts(username, password, sig_cliente).serialize().encode("utf-8")
        )

        resp = self.channel.recv_encrypted_blocking()

        if resp.type != MsgType.OK:
            self.disconnect()
            return Message.error(resp.info or "Autenticação rejeitada.")

        self.username = username
        self.user_id  = resp.user_id or None
        set_logger_user(username)
        self.e2e.set_privkey(client_privkey)
        _clog.info("login bem-sucedido — chave privada RSA decifrada localmente (PBKDF2+ChaCha20-Poly1305), assinatura STS aceite pelo servidor")

        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()

        self._generate_and_upload_prekeys()
        return resp

    def _generate_and_upload_prekeys(self) -> None:
        payload = self.e2e.generate_prekeys_payload()
        self.send(Message.req_prekey_upload(payload))
        resp = self.receive()
        if not resp or resp.type != MsgType.OK:
            _clog.warning("falha ao fazer upload de prekeys ao servidor — outros utilizadores poderão não conseguir iniciar E2E enquanto estiver offline")

    # ── E2E ───────────────────────────────────────────────────────────────────

    def e2e_initiate(self, target: str, bundle: Message) -> str | None:
        return self.e2e.initiate(target, bundle)

    def e2e_receive_init(self, sender: str, payload_b64: str) -> bool:
        return self.e2e.receive_init(sender, payload_b64)

    def e2e_initiate_online(self, target: str, cert_pem: str) -> str | None:
        return self.e2e.initiate_online(target, cert_pem)

    def e2e_receive_dh_resp(self, sender: str, payload_b64: str) -> bool:
        return self.e2e.receive_dh_resp(sender, payload_b64)

    def e2e_receive_dh_init(self, sender: str, payload_b64: str) -> str | None:
        return self.e2e.receive_dh_init(sender, payload_b64)

    def e2e_send_message(self, target: str, plaintext: str) -> str | None:
        return self.e2e.send_message(target, plaintext)

    def e2e_receive_message(self, sender: str, payload_b64: str) -> str | None:
        return self.e2e.receive_message(sender, payload_b64)

    def has_e2e_session(self, target: str) -> bool:
        return self.e2e.has_session(target)

    # ── Grupo: sender keys ────────────────────────────────────────────────────

    def group_generate_sender_key(self, group_name: str):
        return self.group_sk.generate_sender_key(group_name)

    def group_has_sender_key(self, group_name: str) -> bool:
        return self.group_sk.has_sender_key(group_name)

    def group_build_sk_dist_payload(self, group_name: str) -> str | None:
        return self.group_sk.build_sk_dist_payload(group_name)

    def group_receive_sk_dist(self, sender: str, payload_b64: str) -> str | None:
        return self.group_sk.receive_sk_dist(sender, payload_b64)

    def group_discard_sender_key(self, group_name: str) -> None:
        self.group_sk.discard_sender_key(group_name)

    def group_encrypt_message(self, group_name: str, plaintext: str) -> str | None:
        return self.group_sk.encrypt_group_message(group_name, plaintext)

    def group_decrypt_message(self, group_name: str, sender: str, payload_b64: str) -> str | None:
        return self.group_sk.decrypt_group_message(group_name, sender, payload_b64)

    def group_has_recv_key(self, group_name: str, sender: str) -> bool:
        return self.group_sk.has_recv_key(group_name, sender)

    # ── Envio/Recepção ────────────────────────────────────────────────────────

    def _send_ack(self, msg: Message) -> None:
        if self.channel.dh_shared is None or self.channel.is_rekeying:
            return
        try:
            self.channel.send_encrypted(msg.serialize().encode("utf-8"))
        except OSError:
            pass

    def _send_async(self, msg: Message) -> None:
        """Envia E2E_MSG a partir do callback (thread de receive): regista o msg_id para
        que o _receive_loop descarte o OK correspondente em vez de o pôr na queue."""
        if self.channel.dh_shared is None or self.channel.is_rekeying:
            return
        mid = msg.get("msg_id") or msg.payload.get("msg_id")
        if mid:
            with self._async_ids_lock:
                self._async_msg_ids.add(str(mid))
        try:
            self.channel.send_encrypted(msg.serialize().encode("utf-8"))
        except OSError:
            if mid:
                with self._async_ids_lock:
                    self._async_msg_ids.discard(str(mid))

    def send(self, message: Message) -> None:
        if self.channel.dh_shared is None:
            raise RuntimeError("Sem canal seguro.")
        self.channel.check_rekey()
        self.channel.send_encrypted(message.serialize().encode("utf-8"))

    def receive(self) -> Message:
        return self.queue.get()

    def _receive_loop(self) -> None:
        while True:
            try:
                msg = self.channel.recv_encrypted()

                if msg.type == MsgType.REKEY:
                    new_gy_bytes = base64.b64decode(msg.get("gy"))
                    self.channel.handle_rekey_response(new_gy_bytes)
                    continue

                if msg.type in (MsgType.RECEIVE, MsgType.GROUP_RECEIVE) and self.on_message_callback:
                    self.on_message_callback(msg)
                elif msg.type == MsgType.E2E_DELIVER and self.on_message_callback:
                    self.on_message_callback(msg)
                elif msg.type in (MsgType.GROUP_MEMBER_LEFT, MsgType.GROUP_MEMBER_JOINED) and self.on_message_callback:
                    self.on_message_callback(msg)
                elif msg.type == MsgType.OK:
                    mid = msg.get("msg_id")
                    if mid:
                        with self._async_ids_lock:
                            if str(mid) in self._async_msg_ids:
                                self._async_msg_ids.discard(str(mid))
                                continue
                    self.queue.put(msg)
                else:
                    self.queue.put(msg)

            except (ConnectionResetError, OSError):
                self.queue.put(None)
                return
            except Exception as e:
                print(f"[-] Erro na thread de recepção: {e}")
                self.queue.put(None)
                return
