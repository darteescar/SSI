import asyncio
import sys
import os
from datetime import datetime

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from ui.view import ChatView
from app.messaging import MessagingService


class Controller:
    def __init__(self, view: ChatView, messaging: MessagingService):
        self.view      = view
        self.messaging = messaging

        self.messaging.on_message_received       = self._on_message_received
        self.messaging.on_group_message_received = self._on_group_message_received

    # ── Callbacks de mensagens recebidas (push) ───────────────────────────────

    def _on_message_received(self, sender: str, recipient: str, text: str, ts: str) -> None:
        if self.view._mode == "chat" and self.view._target == sender:
            self.view.print_chat_message(sender, recipient, text, ts)

    def _on_group_message_received(self, sender: str, group_display: str, text: str, ts: str) -> None:
        if self.view._mode == "group" and group_display == f"#{self.view._target}":
            self.view.print_chat_message(sender, group_display, text, ts)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _now(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _require_login(self) -> bool:
        if not self.messaging.is_logged_in():
            self.view.print_error("Tens de fazer login primeiro.")
            return False
        return True

    def _show(self, ok: bool, info: str, error: str = "") -> None:
        if ok:
            self.view.print_success(info)
        elif error:
            self.view.print_error(error)

    # ── Autenticação ──────────────────────────────────────────────────────────

    def cmd_login(self, username: str, password: str):
        if not username or not password:
            self.view.print_error("Uso: login <username> <password>")
            return
        if self.messaging.is_logged_in():
            self.view.print_error("Já estás autenticado. Faz logout primeiro.")
            return
        ok, info = self.messaging.login(username, password)
        if ok:
            self.view.set_username(username)
            self.view.print_success(info)
        else:
            self.view.print_error(info)

    def cmd_registo(self, username: str, password: str):
        if not username or not password:
            self.view.print_error("Uso: registo <username> <password>")
            return
        if self.messaging.is_logged_in():
            self.view.print_error("Já estás autenticado. Faz logout primeiro.")
            return
        ok, info = self.messaging.registo(username, password)
        self._show(ok, info, info)

    def cmd_logout(self):
        if not self.messaging.is_logged_in():
            self.view.print_error("Não estás autenticado.")
            return
        if not self.messaging.is_connected():
            self.view.set_logged_out()
            return
        ok, info = self.messaging.logout()
        self._show(ok, info, info)
        self.view.set_logged_out()

    # ── Contactos ─────────────────────────────────────────────────────────────

    def cmd_add(self, username: str):
        if not self._require_login(): return
        if not username:
            self.view.print_error("Uso: add <username>")
            return
        ok, info = self.messaging.add_contact(username)
        self._show(ok, info, info)

    def cmd_remove(self, username: str):
        if not self._require_login(): return
        if not username:
            self.view.print_error("Uso: remove <username>")
            return
        ok, info = self.messaging.remove_contact(username)
        self._show(ok, info, info)

    def cmd_list(self):
        if not self._require_login(): return
        ok, users, err = self.messaging.list_online()
        if ok:
            self.view.print_online(users)
        else:
            self.view.print_error(err)

    def cmd_contacts(self):
        if not self._require_login(): return
        ok, users, err = self.messaging.list_contacts()
        if ok:
            self.view.print_contacts(users)
        else:
            self.view.print_error(err)

    # ── Grupos ────────────────────────────────────────────────────────────────

    def cmd_group(self, args: list[str]):
        if not self._require_login(): return
        if len(args) < 2:
            self.view.print_error("Uso: group <nome> <user1,user2,...>")
            return
        group_name = args[0]
        members    = [m.strip() for m in args[1].split(",") if m.strip()]
        ok, info   = self.messaging.create_group(group_name, members)
        self._show(ok, info, info)

    def cmd_delete_group(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            self.view.print_error("Uso: delete <nome_do_grupo>")
            return
        ok, info = self.messaging.delete_group(group_name)
        self._show(ok, info, info)

    def cmd_leave(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            self.view.print_error("Uso: leave <nome_do_grupo>")
            return
        ok, info = self.messaging.leave_group(group_name)
        self._show(ok, info, info)

    def cmd_groups(self):
        if not self._require_login(): return
        ok, groups, err = self.messaging.list_groups()
        if ok:
            self.view.print_groups(groups)
        else:
            self.view.print_error(err)

    def cmd_accept(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            self.view.print_error("Uso: accept <nome_do_grupo>")
            return
        ok, info = self.messaging.accept_group(group_name)
        self._show(ok, info, info)

    def cmd_reject(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            self.view.print_error("Uso: reject <nome_do_grupo>")
            return
        ok, info = self.messaging.reject_group(group_name)
        self._show(ok, info, info)

    def cmd_group_invites(self):
        if not self._require_login(): return
        ok, invites, err = self.messaging.list_invites()
        if ok:
            self.view.print_invites(invites)
        else:
            self.view.print_error(err)

    def cmd_invite_group_member(self, group_name: str, username: str):
        if not self._require_login(): return
        if not group_name or not username:
            self.view.print_error("Uso: invite <grupo> <user>")
            return
        ok, info = self.messaging.invite_member(group_name, username)
        self._show(ok, info, info)

    def cmd_kick_group_member(self, group_name: str, username: str):
        if not self._require_login(): return
        if not group_name or not username:
            self.view.print_error("Uso: kick <grupo> <user>")
            return
        ok, info = self.messaging.kick_member(group_name, username)
        self._show(ok, info, info)

    # ── Chat ──────────────────────────────────────────────────────────────────

    async def cmd_chat(self, args: list[str]):
        if not self._require_login(): return
        if not args:
            self.view.print_error("Uso: chat <username/groupname>")
            return

        target = args[0]
        session, err = self.messaging.open_chat(target)
        if session is None:
            self.view.print_error(err)
            return

        if session.is_group:
            self.view.set_mode_group(target)
        else:
            self.view.set_mode_chat(target)

        for msg in session.history:
            self.view.print_chat_message(
                msg.get("from_", ""),
                msg.get("to", target),
                msg.get("text", ""),
                msg.get("timestamp", ""),
            )

        await self._chat_loop(session)

    async def _chat_loop(self, session) -> None:
        target   = session.target
        is_group = session.is_group
        me       = self.messaging.username() or ""

        while True:
            try:
                line = await self.view.get_input()
                self.view.clear_input_line()
            except (EOFError, KeyboardInterrupt):
                self.messaging.close_chat(target)
                self.view.set_mode_main()
                break

            text = line.strip()
            if not text:
                continue

            if text.startswith("/"):
                match text.split()[0].lower():
                    case "/exit":
                        self.messaging.close_chat(target)
                        self.view.set_mode_main()
                        break
                    case "/help":
                        self.view.print_info("Comandos de chat: /exit (Sair do chat), /help (Ajuda)")
                    case cmd:
                        self.view.print_error(f"Comando de chat desconhecido: '{cmd}'")
                continue

            timestamp = self._now()
            result    = self.messaging.send_message(target, is_group, text, timestamp)

            if result.lost:
                self.view.print_error(result.error)
                self.view.set_mode_main()
                break
            elif result.ok:
                display_to = f"#{target}" if is_group else target
                self.view.print_chat_message(me, display_to, result.text, timestamp)
            else:
                self.view.print_error(result.error)

    # ── Loops ─────────────────────────────────────────────────────────────────

    async def _auth_loop(self) -> bool:
        while not self.messaging.is_logged_in():
            if not self.messaging.is_connected():
                try:
                    self.messaging.connect()
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

            cmd  = parts[0].lower()
            args = parts[1:]
            arg1 = args[0] if args else ""
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
                self.messaging.disconnect()
        return True

    async def _main_loop(self) -> bool:
        while self.messaging.is_logged_in():
            try:
                line = await self.view.get_input()
            except (EOFError, KeyboardInterrupt):
                if self.messaging.is_logged_in():
                    self.cmd_logout()
                return False

            parts = line.strip().split()
            if not parts:
                continue

            cmd  = parts[0].lower()
            args = parts[1:]
            arg1 = args[0] if args else ""

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
                self.messaging.disconnect()
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
            self.messaging.disconnect()
