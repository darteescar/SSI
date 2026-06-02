import base64
import logging
import threading
from typing import Callable

import sys, os
_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.MsgType import MsgType
from crypto.e2e_session import E2EManager

_log = logging.getLogger("e2e")


class E2ELayer:
    """Camada E2E: estabelecimento de sessão + cifra/decifra por ratchet."""

    def __init__(self, conn, keystore):
        self._conn     = conn      # ServerConnection
        self._keystore = keystore  # Keystore
        self._mgr: E2EManager | None = None  # criado em init()
        self._dh_resp_events: dict[str, threading.Event]       = {}
        self._pending_e2e:    dict[str, list[tuple[str, str]]] = {}

        # callback chamado quando uma mensagem E2E de texto chega
        self.on_message: Callable[[str, str, str, str], None] | None = None

    def init(self, server_cert_path: str) -> None:
        """Constrói o E2EManager com o caminho do certificado do servidor."""
        self._mgr = E2EManager(self._keystore, server_cert_path)

    def set_privkey(self, privkey) -> None:
        self._mgr.set_privkey(privkey)

    def reset(self) -> None:
        self._mgr.reset()
        self._dh_resp_events.clear()
        self._pending_e2e.clear()

    # ── Prekeys ───────────────────────────────────────────────────────────────

    def generate_and_upload_prekeys(self) -> None:
        payload = self._mgr.generate_prekeys_payload()
        resp = self._conn.send(Message.req_prekey_upload(payload))
        if not resp or resp.type != MsgType.OK:
            _log.warning("falha ao fazer upload de prekeys — E2E offline pode não funcionar")

    # ── Sessão E2E ────────────────────────────────────────────────────────────

    def has_session(self, target: str) -> bool:
        return self._mgr.has_session(target)

    def ensure_session(self, target: str) -> tuple[bool, str]:
        if self._mgr.has_session(target):
            return True, ""
        bundle = self._conn.send(Message.req_prekey_request(target))
        if bundle is None:
            return False, "Ligação perdida."
        if bundle.type == MsgType.ERROR:
            return False, bundle.reason or "Não foi possível estabelecer sessão E2E."
        if bundle.type == MsgType.ONLINE_BUNDLE:
            ok = self._establish_online(target, bundle.cert_pem)
            return (True, "") if ok else (False, "Falha ao verificar identidade do destinatário.")
        if bundle.type == MsgType.PREKEY_BUNDLE:
            ok = self._establish_offline(target, bundle)
            if not ok:
                return False, "Falha ao verificar identidade do destinatário."
            if bundle.low_stock:
                self.generate_and_upload_prekeys()
            return True, ""
        return False, "Resposta inesperada do servidor."

    def _establish_online(self, target: str, cert_pem: str) -> bool:
        dh_payload = self._mgr.initiate_online(target, cert_pem)
        if dh_payload is None:
            return False
        ev = threading.Event()
        self._dh_resp_events[target] = ev
        msg_id = self._mgr.new_msg_id()
        ack = self._conn.send(Message.req_e2e_msg(target, msg_id, dh_payload))
        if ack is None or ack.type == MsgType.ERROR:
            self._dh_resp_events.pop(target, None)
            return False
        if not ev.wait(timeout=10):
            self._dh_resp_events.pop(target, None)
            return False
        self._dh_resp_events.pop(target, None)
        return True

    def _establish_offline(self, target: str, bundle) -> bool:
        init_payload = self._mgr.initiate(target, bundle)
        if init_payload is None:
            return False
        msg_id = self._mgr.new_msg_id()
        ack = self._conn.send(Message.req_e2e_msg(target, msg_id, init_payload))
        return ack is not None and ack.type != MsgType.ERROR

    # ── Envio / Recepção de mensagens ─────────────────────────────────────────

    def send_message(self, target: str, text: str) -> tuple[bool, str]:
        payload_b64 = self._mgr.send_message(target, text)
        if payload_b64 is None:
            return False, "Falha ao cifrar mensagem."
        msg_id = self._mgr.new_msg_id()
        ack = self._conn.send(Message.req_e2e_msg(target, msg_id, payload_b64))
        if ack is None:
            return False, "Ligação perdida."
        if ack.type == MsgType.ERROR:
            return False, ack.reason or ""
        return True, ""

    # ── Handlers de mensagens push (chamados pelo MessagingService) ───────────

    def handle_deliver(self, msg: Message) -> None:
        sender      = msg.from_ or "Desconhecido"
        msg_id      = msg.e2e_msg_id
        payload_b64 = msg.payload_b64

        try:
            import json
            raw   = base64.b64decode(payload_b64)
            inner = json.loads(raw.decode("utf-8"))
            ptype = inner.get("type", "msg")
        except Exception:
            ptype = "msg"

        if ptype == "dh_init":
            resp_payload = self._mgr.receive_dh_init(sender, payload_b64)
            if resp_payload:
                resp_id = self._mgr.new_msg_id()
                self._conn.send_async(Message.req_e2e_msg(sender, resp_id, resp_payload))
                self._flush_pending(sender)
            self._conn.send_ack(Message.req_e2e_ack(msg_id))
            return

        if ptype == "dh_resp":
            self._mgr.receive_dh_resp(sender, payload_b64)
            ev = self._dh_resp_events.get(sender)
            if ev:
                ev.set()
            self._conn.send_ack(Message.req_e2e_ack(msg_id))
            return

        if ptype == "init":
            ok = self._mgr.receive_init(sender, payload_b64)
            if ok:
                self._flush_pending(sender)
            self._conn.send_ack(Message.req_e2e_ack(msg_id))
            return

        if not self._mgr.has_session(sender):
            self._pending_e2e.setdefault(sender, []).append((msg_id, payload_b64))
            return

        self._flush_pending(sender)
        self._deliver_text(sender, msg_id, payload_b64)
        self._conn.send_ack(Message.req_e2e_ack(msg_id))

    def _flush_pending(self, sender: str) -> None:
        for pid, ppayload in self._pending_e2e.pop(sender, []):
            self._deliver_text(sender, pid, ppayload)
            self._conn.send_ack(Message.req_e2e_ack(pid))

    def _deliver_text(self, sender: str, msg_id: str, payload_b64: str) -> None:
        text = self._mgr.receive_message(sender, payload_b64)
        if text is None:
            return
        from datetime import datetime
        ts = datetime.now().strftime("%H:%M:%S")
        me = self._conn.username or "?"
        self._keystore.append_history(sender, sender, me, text, ts)
        if self.on_message:
            self.on_message(sender, me, text, ts)

    # ── Acesso ao manager ─────────────────────────────────────────────────────

    def new_msg_id(self) -> str:
        return self._mgr.new_msg_id()
