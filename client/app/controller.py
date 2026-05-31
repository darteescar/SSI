import asyncio
import sys
import os
import threading
from datetime import datetime

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.Message import Message
from common.MsgType import MsgType
from net.network import NetworkClient
from ui.view import ChatView

class Controller:
    def __init__(self, network: NetworkClient, view: ChatView):
        self.network = network
        self.view = view
        self.network.on_message_callback = self.handle_incoming_message
        self._pending_e2e: dict[str, list[tuple[str, str]]] = {}
        self._dh_resp_events: dict[str, threading.Event] = {}

    def handle_incoming_message(self, msg: Message):
        if msg.type == MsgType.E2E_DELIVER:
            sender      = msg.from_ or "Desconhecido"
            msg_id      = msg.e2e_msg_id
            payload_b64 = msg.payload_b64

            import base64, json as _json
            try:
                raw = base64.b64decode(payload_b64)
                inner = _json.loads(raw.decode("utf-8"))
                ptype = inner.get("type", "")
            except Exception:
                ptype = "msg"

            if ptype == "sk_dist":
                group_name = self.network.group_receive_sk_dist(sender, payload_b64)
                if group_name:
                    import logging as _logging
                    _logging.getLogger("network").info(
                         f"[GroupSK] sender key de '{sender}' para grupo '{group_name}' processada")
                self.network._send_ack(Message.req_e2e_ack(msg_id))
                return
            elif ptype == "dh_init":
                resp_payload = self.network.e2e_receive_dh_init(sender, payload_b64)
                if resp_payload:
                    resp_msg_id = self.network.e2e.new_msg_id()
                    self.network._send_async(Message.req_e2e_msg(sender, resp_msg_id, resp_payload))
                    for pending_id, pending_payload in self._pending_e2e.pop(sender, []):
                        pending_text = self.network.e2e_receive_message(sender, pending_payload)
                        if pending_text is not None:
                            ts = self._now()
                            me = self.network.username or "?"
                            self.network.keystore.append_history(sender, sender, me, pending_text, ts)
                            if self.view._mode == "chat" and self.view._target == sender:
                                self.view.print_chat_message(sender, me, pending_text, ts)
                        self.network._send_ack(Message.req_e2e_ack(pending_id))
                self.network._send_ack(Message.req_e2e_ack(msg_id))
                return
            elif ptype == "dh_resp":
                self.network.e2e_receive_dh_resp(sender, payload_b64)
                ev = self._dh_resp_events.get(sender)
                if ev:
                    ev.set()
                self.network._send_ack(Message.req_e2e_ack(msg_id))
                return
            elif ptype == "init":
                ok = self.network.e2e_receive_init(sender, payload_b64)
                if ok:
                    for pending_id, pending_payload in self._pending_e2e.pop(sender, []):
                        pending_text = self.network.e2e_receive_message(sender, pending_payload)
                        if pending_text is not None:
                            ts = self._now()
                            me = self.network.username or "?"
                            self.network.keystore.append_history(sender, sender, me, pending_text, ts)
                            if self.view._mode == "chat" and self.view._target == sender:
                                self.view.print_chat_message(sender, me, pending_text, ts)
                        self.network._send_ack(Message.req_e2e_ack(pending_id))
            else:
                if not self.network.has_e2e_session(sender):
                    self._pending_e2e.setdefault(sender, []).append((msg_id, payload_b64))
                    return
                for pending_id, pending_payload in self._pending_e2e.pop(sender, []):
                    pending_text = self.network.e2e_receive_message(sender, pending_payload)
                    if pending_text is not None:
                        timestamp = self._now()
                        me = self.network.username or "?"
                        self.network.keystore.append_history(sender, sender, me, pending_text, timestamp)
                        if self.view._mode == "chat" and self.view._target == sender:
                            self.view.print_chat_message(sender, me, pending_text, timestamp)
                    self.network._send_ack(Message.req_e2e_ack(pending_id))
                text = self.network.e2e_receive_message(sender, payload_b64)
                if text is not None:
                    timestamp = self._now()
                    me = self.network.username or "?"
                    self.network.keystore.append_history(sender, sender, me, text, timestamp)
                    if self.view._mode == "chat" and self.view._target == sender:
                        self.view.print_chat_message(sender, me, text, timestamp)

            self.network._send_ack(Message.req_e2e_ack(msg_id))

        elif msg.type == MsgType.RECEIVE:
            sender    = msg.from_ or "Desconhecido"
            recipient = msg.to or "Desconhecido"
            text      = msg.text
            timestamp = msg.timestamp or self._now()
            self.view.print_chat_message(sender, recipient, text, timestamp)
        elif msg.type == MsgType.GROUP_RECEIVE:
            sender     = msg.from_ or "Desconhecido"
            group_name = msg.group_name or "?"
            payload_b64 = msg.payload_b64
            timestamp  = msg.timestamp or self._now()
            msg_id     = msg.msg_id
            text = self.network.group_decrypt_message(group_name, sender, payload_b64)
            if text is None:
                text = "[mensagem cifrada — sender key não disponível]"
            self.network.keystore.append_history(group_name, sender, f"#{group_name}", text, timestamp)
            if self.view._mode == "group" and self.view._target == group_name:
                self.view.print_chat_message(sender, f"#{group_name}", text, timestamp)
            self.network._send_ack(Message.req_group_ack(group_name, msg_id))
        elif msg.type == MsgType.GROUP_MEMBER_LEFT:
            group_name = msg.group_name or ""
            left_user  = msg.info or "?"
            if group_name:
                threading.Thread(
                    target=self._rotate_sender_key,
                    args=(group_name, left_user),
                    daemon=True,
                ).start()
        elif msg.type == MsgType.GROUP_MEMBER_JOINED:
            group_name = msg.group_name or ""
            new_member = msg.info or "?"
            if group_name and new_member and new_member != self.network.username:
                if self.network.group_has_sender_key(group_name):
                    threading.Thread(
                        target=self._distribute_sender_key_to,
                        args=(group_name, new_member),
                        daemon=True,
                    ).start()

    def _rotate_sender_key(self, group_name: str, left_user: str) -> None:
        import logging as _logging
        log = _logging.getLogger("network")
        log.info(f"[GroupSK] '{left_user}' saiu de '{group_name}' — a rodar sender key")
        self.network.group_discard_sender_key(group_name)
        self.network.group_generate_sender_key(group_name)
        self.network.send(Message.req_groups())
        groups_resp = self.network.receive()
        if groups_resp and groups_resp.type == MsgType.OK:
            members = groups_resp.groups.get(group_name, [])
            for member in members:
                if member != self.network.username and member != left_user:
                    self._distribute_sender_key_to(group_name, member)
        log.info(f"[GroupSK] rotação de sender key de '{group_name}' concluída")

    def _now(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _establish_e2e_session(self, target: str) -> bool:
        if self.network.has_e2e_session(target):
            return True
        self.network.send(Message.req_prekey_request(target))
        bundle = self.network.receive()
        if bundle is None:
            return False
        if bundle.type == MsgType.ONLINE_BUNDLE:
            dh_payload = self.network.e2e_initiate_online(target, bundle.cert_pem)
            if dh_payload is None:
                return False
            ev = threading.Event()
            self._dh_resp_events[target] = ev
            msg_id = self.network.e2e.new_msg_id()
            self.network.send(Message.req_e2e_msg(target, msg_id, dh_payload))
            ack = self.network.receive()
            if ack is None or ack.type == MsgType.ERROR:
                self._dh_resp_events.pop(target, None)
                return False
            if not ev.wait(timeout=10):
                self._dh_resp_events.pop(target, None)
                return False
            self._dh_resp_events.pop(target, None)
            return True
        elif bundle.type == MsgType.PREKEY_BUNDLE:
            init_payload = self.network.e2e_initiate(target, bundle)
            if init_payload is None:
                return False
            msg_id = self.network.e2e.new_msg_id()
            self.network.send(Message.req_e2e_msg(target, msg_id, init_payload))
            ack = self.network.receive()
            if ack is None or ack.type == MsgType.ERROR:
                return False
            if bundle.low_stock:
                self.network._generate_and_upload_prekeys()
            return True
        return False

    def _distribute_sender_key_to(self, group_name: str, member: str) -> bool:
        if not self._establish_e2e_session(member):
            return False
        payload_b64 = self.network.group_build_sk_dist_payload(group_name)
        if payload_b64 is None:
            return False
        msg_id = self.network.e2e.new_msg_id()
        try:
            self.network.send(Message.req_e2e_msg(member, msg_id, payload_b64))
            ack = self.network.receive()
            return ack is not None and ack.type == MsgType.OK
        except OSError:
            return False

    def _ensure_group_sender_key(self, group_name: str, members: list[str]) -> None:
        if not self.network.group_has_sender_key(group_name):
            self.network.group_generate_sender_key(group_name)
        for member in members:
            if member == self.network.username:
                continue
            self._distribute_sender_key_to(group_name, member)

    def _is_logged_in(self) -> bool:
        return self.network.is_logged_in()

    def _is_connected(self) -> bool:
        return self.network.transport.socket is not None

    def _require_login(self) -> bool:
        if not self._is_logged_in():
            self.view.print_error("Tens de fazer login primeiro.")
            return False
        return True

    def _request_simple(self, req: Message):
        self.network.send(req)
        resp = self.network.receive()
        if resp and resp.type == MsgType.OK:
            self.view.print_success(resp.info)
        elif resp and resp.type == MsgType.ERROR:
            self.view.print_error(resp.reason)
        return resp

    # ── Autenticação ──────────────────────────────────────────────────────────

    def cmd_login(self, username: str, password: str):
        if not username or not password:
            self.view.print_error("Uso: login <username> <password>")
            return
        if self._is_logged_in():
            self.view.print_error("Já estás autenticado. Faz logout primeiro.")
            return
        response = self.network.login(username, password)
        if response.type == MsgType.OK:
            self.view.set_username(username)
            self.view.print_success(response.info)
        else:
            self.view.print_error(response.reason)

    def cmd_registo(self, username: str, password: str):
        if not username or not password:
            self.view.print_error("Uso: registo <username> <password>")
            return
        if self._is_logged_in():
            self.view.print_error("Já estás autenticado. Faz logout primeiro.")
            return
        msg = self.network.registo(username, password)
        if msg and msg.type == MsgType.OK:
            self.view.print_success(msg.info)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)
        elif msg is None:
            self.view.print_error("Resposta do servidor inválida.")

    def cmd_logout(self):
        if not self._is_logged_in():
            self.view.print_error("Não estás autenticado.")
            return
        if not self._is_connected():
            self.view.set_logged_out()
            return
        try:
            self.network.send(Message.req_logout())
            msg = self.network.receive()
            if msg and msg.type == MsgType.OK:
                self.view.print_success(msg.info)
            elif msg and msg.type == MsgType.ERROR:
                self.view.print_error(msg.reason)
            elif msg is None:
                self.view.print_error("Não foi possível receber confirmação do servidor.")
        finally:
            self.network.disconnect()
            self.view.set_logged_out()

    # ── Contactos ─────────────────────────────────────────────────────────────

    def cmd_add(self, username: str):
        if not self._require_login(): return
        if not username:
            self.view.print_error("Uso: add <username>")
            return
        self.network.send(Message.req_add(username))
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.view.print_success(msg.info)
            cert_pem = msg.cert_pem
            if cert_pem:
                self.network.keystore.save_contact_cert(username, cert_pem)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)

    def cmd_remove(self, username: str):
        if not self._require_login(): return
        if not username:
            self.view.print_error("Uso: remove <username>")
            return
        self._request_simple(Message.req_remove(username))

    def cmd_list(self):
        if not self._require_login(): return
        self.network.send(Message.req_list_online())
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.view.print_online(msg.users)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)

    def cmd_contacts(self):
        if not self._require_login(): return
        self.network.send(Message.req_contacts())
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.view.print_contacts(msg.users)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)

    # ── Grupos ────────────────────────────────────────────────────────────────

    def cmd_group(self, args: list[str]):
        if not self._require_login(): return
        if len(args) < 2:
            self.view.print_error("Uso: group <nome> <user1,user2,...>")
            return
        group_name = args[0]
        members = args[1].split(",")
        self.network.send(Message.req_create_group(group_name, members))
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.view.print_success(msg.info)
            self.network.group_generate_sender_key(group_name)
            for member in members:
                member = member.strip()
                if member and member != self.network.username:
                    self._distribute_sender_key_to(group_name, member)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)

    def cmd_delete_group(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            self.view.print_error("Uso: delete <nome_do_grupo>")
            return
        self._request_simple(Message.req_delete_group(group_name))

    def cmd_leave(self, args: str):
        if not self._require_login(): return
        group_name = args.strip()
        if not group_name:
            self.view.print_error("Uso: leave <nome_do_grupo>")
            return
        self.network.send(Message.req_leave_group(group_name))
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.view.print_success(msg.info)
            self.network.group_discard_sender_key(group_name)
            self.network.keystore.delete_history(group_name)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)

    def cmd_groups(self):
        if not self._require_login(): return
        self.network.send(Message.req_groups())
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.view.print_groups(msg.groups)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)

    def cmd_accept(self, arg: str):
        if not self._require_login(): return
        if not arg:
            self.view.print_error("Uso: accept <nome_do_grupo>")
            return
        self.network.send(Message.req_accept_group(arg))
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.view.print_success(msg.info)
            # Gerar sender key própria e distribuí-la a todos os membros actuais
            self.network.send(Message.req_groups())
            groups_resp = self.network.receive()
            if groups_resp and groups_resp.type == MsgType.OK:
                members = groups_resp.groups.get(arg, [])
                self.network.group_generate_sender_key(arg)
                for member in members:
                    if member != self.network.username:
                        self._distribute_sender_key_to(arg, member)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)

    def cmd_reject(self, arg: str):
        if not self._require_login(): return
        if not arg:
            self.view.print_error("Uso: reject <nome_do_grupo>")
            return
        self._request_simple(Message.req_reject_group(arg))

    def cmd_group_invites(self):
        if not self._require_login(): return
        self.network.send(Message.req_group_invites())
        msg = self.network.receive()
        if msg and msg.type == MsgType.OK:
            self.view.print_invites(msg.invites)
        elif msg and msg.type == MsgType.ERROR:
            self.view.print_error(msg.reason)

    def cmd_invite_group_member(self, group_name: str, username: str):
        if not self._require_login(): return
        if not group_name or not username:
            self.view.print_error("Uso: invite <grupo> <user>")
            return
        self._request_simple(Message.req_add_group_member(group_name, username))

    def cmd_kick_group_member(self, group_name: str, username: str):
        if not self._require_login(): return
        if not group_name or not username:
            self.view.print_error("Uso: kick <grupo> <user>")
            return
        self._request_simple(Message.req_kick_group_member(group_name, username))

    # ── Chat ──────────────────────────────────────────────────────────────────

    async def cmd_chat(self, args: list[str]):
        if not self._require_login(): return
        if len(args) < 1:
            self.view.print_error("Uso: chat <username/groupname>")
            return
        target = args[0]

        self.network.send(Message.req_chat(target))
        response = self.network.receive()

        if response is None:
            self.view.print_error("Ligação perdida.")
            return
        if response.type == MsgType.ERROR:
            self.view.print_error(response.reason)
            return

        is_group = response.is_group

        e2e_ready = False
        if not is_group:
            if self.network.has_e2e_session(target):
                e2e_ready = True
            else:
                self.network.send(Message.req_prekey_request(target))
                bundle = self.network.receive()
                if bundle is None:
                    self.view.print_error("Ligação perdida.")
                    return
                if bundle.type == MsgType.ONLINE_BUNDLE:
                    dh_payload = self.network.e2e_initiate_online(target, bundle.cert_pem)
                    if dh_payload is None:
                        self.view.print_error("Falha ao verificar identidade do destinatário.")
                        return
                    ev = threading.Event()
                    self._dh_resp_events[target] = ev
                    msg_id = self.network.e2e.new_msg_id()
                    self.network.send(Message.req_e2e_msg(target, msg_id, dh_payload))
                    ack = self.network.receive()
                    if ack is None or ack.type == MsgType.ERROR:
                        self._dh_resp_events.pop(target, None)
                        self.view.print_error("Falha ao enviar dh_init.")
                        return
                    if not ev.wait(timeout=10):
                        self._dh_resp_events.pop(target, None)
                        self.view.print_error("[E2E] Timeout a aguardar resposta DH de B.")
                        return
                    self._dh_resp_events.pop(target, None)
                    e2e_ready = True
                elif bundle.type == MsgType.PREKEY_BUNDLE:
                    init_payload = self.network.e2e_initiate(target, bundle)
                    if init_payload is None:
                        self.view.print_error("Falha ao verificar identidade do destinatário.")
                        return
                    msg_id = self.network.e2e.new_msg_id()
                    self.network.send(Message.req_e2e_msg(target, msg_id, init_payload))
                    ack = self.network.receive()
                    if ack is None or ack.type == MsgType.ERROR:
                        self.view.print_error("Falha ao enviar payload E2E de iniciação.")
                        return
                    e2e_ready = True
                    if bundle.low_stock:
                        self.view.print_info("[E2E] Stock de prekeys baixo — a repor...")
                        self.network._generate_and_upload_prekeys()
                elif bundle.type == MsgType.ERROR:
                    self.view.print_error(bundle.reason or "Não foi possível estabelecer sessão E2E.")
                    return

        if is_group:
            self.network.send(Message.req_groups())
            groups_resp = self.network.receive()
            group_members: list[str] = []
            if groups_resp and groups_resp.type == MsgType.OK:
                group_members = [
                    m for m in groups_resp.groups.get(target, [])
                    if m != self.network.username
                ]
            self._ensure_group_sender_key(target, group_members)
            self.view.set_mode_group(target)
        else:
            self.view.set_mode_chat(target)

        for message in self.network.keystore.load_history(target):
            self.view.print_chat_message(
                message.get("from_", ""),
                message.get("to", target),
                message.get("text", ""),
                message.get("timestamp", ""),
            )

        while True:
            try:
                line = await self.view.get_input()
                self.view.clear_input_line()
            except (EOFError, KeyboardInterrupt):
                try:
                    self.network.send(Message.req_chat_leave(target))
                except OSError:
                    pass
                self.view.set_mode_main()
                break

            text = line.strip()
            if not text:
                continue

            if text.startswith("/"):
                cmd = text.split()[0].lower()
                match cmd:
                    case "/exit":
                        self.network.send(Message.req_chat_leave(target))
                        self.view.set_mode_main()
                        break
                    case "/help":
                        self.view.print_info("Comandos de chat: /exit (Sair do chat), /help (Ajuda)")
                    case _:
                        self.view.print_error(f"Comando de chat desconhecido: '{cmd}'")
            else:
                timestamp = self._now()
                me = self.view._username or ""
                if is_group:
                    payload_b64 = self.network.group_encrypt_message(target, text)
                    if payload_b64 is None:
                        self.view.print_error("[GroupSK] Sem sender key — não é possível cifrar. Usa /exit e entra de novo no chat.")
                        continue
                    self.network.send(Message.req_group_send(target, payload_b64, timestamp))
                    response = self.network.receive()
                    if response is None:
                        self.view.print_error("Ligação perdida.")
                        self.view.set_mode_main()
                        break
                    elif response.type == MsgType.OK:
                        self.network.keystore.append_history(target, me, f"#{target}", text, timestamp)
                        self.view.print_chat_message(me, f"#{target}", text, timestamp)
                    elif response.type == MsgType.ERROR:
                        self.view.print_error(response.reason)
                elif e2e_ready:
                    payload_b64 = self.network.e2e_send_message(target, text)
                    if payload_b64 is None:
                        self.view.print_error("[E2E] Falha ao cifrar mensagem.")
                        continue
                    msg_id = self.network.e2e.new_msg_id()
                    self.network.send(Message.req_e2e_msg(target, msg_id, payload_b64))
                    ack = self.network.receive()
                    if ack is None:
                        self.view.print_error("Ligação perdida.")
                        self.view.set_mode_main()
                        break
                    elif ack.type == MsgType.OK:
                        self.network.keystore.append_history(target, me, target, text, timestamp)
                        self.view.print_chat_message(me, target, text, timestamp)
                    elif ack.type == MsgType.ERROR:
                        self.view.print_error(ack.reason)
                else:
                    self.network.send(Message.req_send(me, target, text, timestamp))
                    response = self.network.receive()
                    if response is None:
                        self.view.print_error("Ligação perdida.")
                        self.view.set_mode_main()
                        break
                    elif response.type == MsgType.OK:
                        self.network.keystore.append_history(target, me, target, text, timestamp)
                        self.view.print_chat_message(me, target, text, timestamp)
                    elif response.type == MsgType.ERROR:
                        self.view.print_error(response.reason)

    # ── Loops ────────────────────────────────────────────────────────────────

    async def _auth_loop(self) -> bool:
        while not self._is_logged_in():
            if not self._is_connected():
                try:
                    self.network.connect()
                except Exception as e:
                    self.view.print_error(f"Erro ao conectar: {e}")
                    return False

            try:
                line = await self.view.get_input()
            except (EOFError, KeyboardInterrupt):
                return False

            parts = line.strip().split()
            if not parts:
                continue

            cmd, args = parts[0].lower(), parts[1:]
            arg1 = args[0] if len(args) > 0 else ""
            arg2 = args[1] if len(args) > 1 else ""

            try:
                match cmd:
                    case "help":
                        self.view.show_help()
                    case "login":
                        self.cmd_login(arg1, arg2)
                    case "registo":
                        self.cmd_registo(arg1, arg2)
                    case "exit":
                        return False
                    case _:
                        self.view.print_error("Deves fazer login ou registo primeiro. Comandos: login, registo, help, exit")
            except (BrokenPipeError, OSError, ConnectionResetError) as e:
                self.view.print_error(f"Conexão perdida: {e}")
                self.network.disconnect()
        return True

    async def _main_loop(self) -> bool:
        while self._is_logged_in():
            try:
                line = await self.view.get_input()
            except (EOFError, KeyboardInterrupt):
                if self._is_logged_in():
                    self.cmd_logout()
                return False

            parts = line.strip().split()
            if not parts:
                continue

            cmd, args = parts[0].lower(), parts[1:]
            arg1 = args[0] if len(args) > 0 else ""

            try:
                match cmd:
                    case "help":
                        self.view.show_help()
                    case "logout":
                        self.cmd_logout()
                        return True
                    case "exit":
                        self.cmd_logout()
                        return False
                    case "add":
                        self.cmd_add(arg1)
                    case "remove":
                        self.cmd_remove(arg1)
                    case "contacts":
                        self.cmd_contacts()
                    case "list":
                        self.cmd_list()
                    case "chat":
                        await self.cmd_chat(args)
                    case "group":
                        self.cmd_group(args)
                    case "delete":
                        self.cmd_delete_group(arg1)
                    case "leave":
                        self.cmd_leave(arg1)
                    case "groups":
                        self.cmd_groups()
                    case "accept":
                        self.cmd_accept(arg1)
                    case "reject":
                        self.cmd_reject(arg1)
                    case "invites":
                        self.cmd_group_invites()
                    case "invite":
                        arg2 = args[1] if len(args) > 1 else ""
                        self.cmd_invite_group_member(arg1, arg2)
                    case "kick":
                        arg2 = args[1] if len(args) > 1 else ""
                        self.cmd_kick_group_member(arg1, arg2)
                    case "login" | "registo":
                        self.view.print_error("Já estás autenticado. Faz logout primeiro.")
                    case _:
                        self.view.print_error(f"Comando desconhecido: '{cmd}'. Escreva 'help'")
            except (BrokenPipeError, OSError, ConnectionResetError) as e:
                self.view.print_error(f"Conexão perdida: {e}")
                self.network.disconnect()
                self.view.set_logged_out()
                return True
        return True

    async def run(self):
        try:
            self.view.set_mode_main()
            while True:
                if not await self._auth_loop():
                    break
                if not await self._main_loop():
                    break
        finally:
            self.network.disconnect()
