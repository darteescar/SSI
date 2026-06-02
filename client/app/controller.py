"""Controller — UI + comandos do utilizador.

Cada comando que comunica com o servidor é executado via run_in_executor,
i.e., numa thread separada do asyncio event loop. O acesso à view é sempre
feito com ui_lock adquirido para evitar sobreposição com mensagens push.
"""

import asyncio
import sys
import os
import threading
from datetime import datetime

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from ui.view import ChatView
from app.messaging import MessagingService


class Controller:
    def __init__(self, view: ChatView, messaging: MessagingService,
                 ui_lock: threading.Lock):
        self.view      = view
        self.messaging = messaging
        self._ui_lock  = ui_lock

        self.messaging.on_message_received       = self._on_message_received
        self.messaging.on_group_message_received = self._on_group_message_received

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _now(self) -> str:
        return datetime.now().strftime("%H:%M:%S")

    def _require_login(self) -> bool:
        if not self.messaging.is_logged_in():
            with self._ui_lock:
                self.view.print_error("Tens de fazer login primeiro.")
            return False
        return True

    def _show(self, ok: bool, info: str) -> None:
        with self._ui_lock:
            if ok:
                self.view.print_success(info)
            else:
                self.view.print_error(info)

    async def _run(self, fn, *args):
        """Executa fn(*args) numa thread separada e aguarda o resultado."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, fn, *args)

    # ── Callbacks de mensagens recebidas (push, já chamadas com ui_lock) ──────

    def _on_message_received(self, sender: str, recipient: str, text: str, ts: str) -> None:
        if self.view.is_viewing(sender, is_group=False):
            self.view.print_chat_message(sender, recipient, text, ts)

    def _on_group_message_received(self, sender: str, group_display: str, text: str, ts: str) -> None:
        group_name = group_display.lstrip("#")
        if self.view.is_viewing(group_name, is_group=True):
            self.view.print_chat_message(sender, group_display, text, ts)

    # ── Autenticação ──────────────────────────────────────────────────────────

    async def cmd_login(self, username: str, password: str):
        if not username or not password:
            with self._ui_lock: self.view.print_error("Uso: login <username> <password>")
            return
        if self.messaging.is_logged_in():
            with self._ui_lock: self.view.print_error("Já estás autenticado. Faz logout primeiro.")
            return
        ok, info = await self._run(self.messaging.login, username, password)
        if ok:
            with self._ui_lock:
                self.view.set_username(username)
                self.view.print_success(info)
        else:
            with self._ui_lock: self.view.print_error(info)

    async def cmd_registo(self, username: str, password: str):
        if not username or not password:
            with self._ui_lock: self.view.print_error("Uso: registo <username> <password>")
            return
        if self.messaging.is_logged_in():
            with self._ui_lock: self.view.print_error("Já estás autenticado. Faz logout primeiro.")
            return
        ok, info = await self._run(self.messaging.registo, username, password)
        self._show(ok, info)

    async def cmd_logout(self):
        if not self.messaging.is_logged_in():
            with self._ui_lock: self.view.print_error("Não estás autenticado.")
            return
        if not self.messaging.is_connected():
            with self._ui_lock: self.view.set_logged_out()
            return
        ok, info = await self._run(self.messaging.logout)
        self._show(ok, info)
        with self._ui_lock: self.view.set_logged_out()

    # ── Contactos ─────────────────────────────────────────────────────────────

    async def cmd_add(self, username: str):
        if not self._require_login(): return
        if not username:
            with self._ui_lock: self.view.print_error("Uso: add <username>")
            return
        ok, info = await self._run(self.messaging.add_contact, username)
        self._show(ok, info)

    async def cmd_remove(self, username: str):
        if not self._require_login(): return
        if not username:
            with self._ui_lock: self.view.print_error("Uso: remove <username>")
            return
        ok, info = await self._run(self.messaging.remove_contact, username)
        self._show(ok, info)

    async def cmd_list(self):
        if not self._require_login(): return
        ok, users, err = await self._run(self.messaging.list_online)
        with self._ui_lock:
            if ok:
                self.view.print_online(users)
            else:
                self.view.print_error(err)

    async def cmd_contacts(self):
        if not self._require_login(): return
        ok, users, err = await self._run(self.messaging.list_contacts)
        with self._ui_lock:
            if ok:
                self.view.print_contacts(users)
            else:
                self.view.print_error(err)

    # ── Grupos ────────────────────────────────────────────────────────────────

    async def cmd_group(self, args: list[str]):
        if not self._require_login(): return
        if len(args) < 2:
            with self._ui_lock: self.view.print_error("Uso: group <nome> <user1,user2,...>")
            return
        group_name = args[0]
        members    = [m.strip() for m in args[1].split(",") if m.strip()]
        ok, info   = await self._run(self.messaging.create_group, group_name, members)
        self._show(ok, info)

    async def cmd_delete_group(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            with self._ui_lock: self.view.print_error("Uso: delete <nome_do_grupo>")
            return
        ok, info = await self._run(self.messaging.delete_group, group_name)
        self._show(ok, info)

    async def cmd_leave(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            with self._ui_lock: self.view.print_error("Uso: leave <nome_do_grupo>")
            return
        ok, info = await self._run(self.messaging.leave_group, group_name)
        self._show(ok, info)

    async def cmd_groups(self):
        if not self._require_login(): return
        ok, groups, err = await self._run(self.messaging.list_groups)
        with self._ui_lock:
            if ok:
                self.view.print_groups(groups)
            else:
                self.view.print_error(err)

    async def cmd_accept(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            with self._ui_lock: self.view.print_error("Uso: accept <nome_do_grupo>")
            return
        ok, info = await self._run(self.messaging.accept_group, group_name)
        self._show(ok, info)

    async def cmd_reject(self, group_name: str):
        if not self._require_login(): return
        if not group_name:
            with self._ui_lock: self.view.print_error("Uso: reject <nome_do_grupo>")
            return
        ok, info = await self._run(self.messaging.reject_group, group_name)
        self._show(ok, info)

    async def cmd_group_invites(self):
        if not self._require_login(): return
        ok, invites, err = await self._run(self.messaging.list_invites)
        with self._ui_lock:
            if ok:
                self.view.print_invites(invites)
            else:
                self.view.print_error(err)

    async def cmd_invite_group_member(self, group_name: str, username: str):
        if not self._require_login(): return
        if not group_name or not username:
            with self._ui_lock: self.view.print_error("Uso: invite <grupo> <user>")
            return
        ok, info = await self._run(self.messaging.invite_member, group_name, username)
        self._show(ok, info)

    async def cmd_kick_group_member(self, group_name: str, username: str):
        if not self._require_login(): return
        if not group_name or not username:
            with self._ui_lock: self.view.print_error("Uso: kick <grupo> <user>")
            return
        ok, info = await self._run(self.messaging.kick_member, group_name, username)
        self._show(ok, info)

    # ── Chat ──────────────────────────────────────────────────────────────────

    async def cmd_chat(self, args: list[str]):
        if not self._require_login(): return
        if not args:
            with self._ui_lock: self.view.print_error("Uso: chat <username/groupname>")
            return

        target = args[0]
        session, err = await self._run(self.messaging.open_chat, target)
        if session is None:
            with self._ui_lock: self.view.print_error(err)
            return

        with self._ui_lock:
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
                with self._ui_lock:
                    self.view.clear_input_line()
            except (EOFError, KeyboardInterrupt):
                await self._run(self.messaging.close_chat, target)
                with self._ui_lock: self.view.set_mode_main()
                break

            text = line.strip()
            if not text:
                continue

            if text.startswith("/"):
                match text.split()[0].lower():
                    case "/exit":
                        await self._run(self.messaging.close_chat, target)
                        with self._ui_lock: self.view.set_mode_main()
                        break
                    case "/help":
                        with self._ui_lock:
                            self.view.print_info("Comandos de chat: /exit (Sair do chat), /help (Ajuda)")
                    case cmd:
                        with self._ui_lock:
                            self.view.print_error(f"Comando de chat desconhecido: '{cmd}'")
                continue

            timestamp = self._now()
            result    = await self._run(
                self.messaging.send_message, target, is_group, text, timestamp
            )

            with self._ui_lock:
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
                    await self._run(self.messaging.connect)
                except Exception as e:
                    with self._ui_lock: self.view.print_error(f"Erro ao conectar: {e}")
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
                        with self._ui_lock: self.view.show_help()
                    case "login":
                        await self.cmd_login(arg1, arg2)
                    case "registo":
                        await self.cmd_registo(arg1, arg2)
                    case "exit":
                        return False
                    case _:
                        with self._ui_lock:
                            self.view.print_error("Deves fazer login ou registo primeiro. Comandos: login, registo, help, exit")
            except (BrokenPipeError, OSError, ConnectionResetError) as e:
                with self._ui_lock: self.view.print_error(f"Conexão perdida: {e}")
                await self._run(self.messaging.disconnect)
        return True

    async def _main_loop(self) -> bool:
        while self.messaging.is_logged_in():
            try:
                line = await self.view.get_input()
            except (EOFError, KeyboardInterrupt):
                if self.messaging.is_logged_in():
                    await self.cmd_logout()
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
                        with self._ui_lock: self.view.show_help()
                    case "logout":
                        await self.cmd_logout()
                        return True
                    case "exit":
                        await self.cmd_logout()
                        return False
                    case "add":
                        await self.cmd_add(arg1)
                    case "remove":
                        await self.cmd_remove(arg1)
                    case "contacts":
                        await self.cmd_contacts()
                    case "list":
                        await self.cmd_list()
                    case "chat":
                        await self.cmd_chat(args)
                    case "group":
                        await self.cmd_group(args)
                    case "delete":
                        await self.cmd_delete_group(arg1)
                    case "leave":
                        await self.cmd_leave(arg1)
                    case "groups":
                        await self.cmd_groups()
                    case "accept":
                        await self.cmd_accept(arg1)
                    case "reject":
                        await self.cmd_reject(arg1)
                    case "invites":
                        await self.cmd_group_invites()
                    case "invite":
                        arg2 = args[1] if len(args) > 1 else ""
                        await self.cmd_invite_group_member(arg1, arg2)
                    case "kick":
                        arg2 = args[1] if len(args) > 1 else ""
                        await self.cmd_kick_group_member(arg1, arg2)
                    case "login" | "registo":
                        with self._ui_lock: self.view.print_error("Já estás autenticado. Faz logout primeiro.")
                    case _:
                        with self._ui_lock: self.view.print_error(f"Comando desconhecido: '{cmd}'. Escreva 'help'")
            except (BrokenPipeError, OSError, ConnectionResetError) as e:
                with self._ui_lock:
                    self.view.print_error(f"Conexão perdida: {e}")
                    self.view.set_logged_out()
                await self._run(self.messaging.disconnect)
                return True
        return True

    async def run(self):
        try:
            with self._ui_lock: self.view.set_mode_main()
            while True:
                if not await self._auth_loop():
                    break
                if not await self._main_loop():
                    break
        finally:
            await self._run(self.messaging.disconnect)
