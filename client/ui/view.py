import sys
import os

_CLIENT_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import clear

from ui.views.base import STYLE, esc, print_error, print_success, print_info, print_separator
from ui.views.main_panel import MainPanelView
from ui.views.chat_panel import ChatPanelView
from ui.views.group_panel import GroupPanelView

COMMANDS = ["help", "registo", "login", "logout", "add", "contacts", "exit", "list", "remove", "chat", "group", "delete", "leave", "groups", "accept", "reject", "invites", "invite", "kick"]

class ChatView:
    def __init__(self):
        self._username: str | None = None
        self._mode: str = "main"
        self._target: str = ""
        self.session = PromptSession(
            history=InMemoryHistory(),
            completer=WordCompleter(COMMANDS, ignore_case=True),
            style=STYLE,
        )

    def print_error(self, text: str): print_error(text)
    def print_success(self, text: str): print_success(text)
    def print_info(self, text: str): print_info(text)
    def print_separator(self): print_separator()

    def print_contacts(self, contacts: list[str]): MainPanelView.print_contacts(contacts)
    def print_invites(self, invites: list[dict]): MainPanelView.print_invites(invites)
    def print_online(self, users: list[str]): MainPanelView.print_online(users)
    def print_groups(self, groups: dict[str, list[str]]): MainPanelView.print_groups(groups)

    def show_welcome(self): MainPanelView.show_welcome()

    def show_help(self):
        cmds = [
            ("─────────AUTENTICAÇÃO─────────", ""),
            (" ", ""),
            ("registo <username> <password>", "   Criar nova conta"),
            ("login   <user>", "        Autenticar na conta"),
            ("logout", "  Terminar sessão"),
            (" ", ""),
            ("───────────CONTACTOS──────────", ""),
            (" ", ""),
            ("add    <user>", "        Adicionar contacto"),
            ("remove <user>", "        Remover contacto"),
            ("contacts", "  Listar contactos"),
            ("list", "  Listar utilizadores online"),
            (" ", ""),
            ("─────────────CHAT─────────────", ""),
            (" ", ""),
            ("chat   <user/grupo>", "        Abrir modo de chat"),
            (" ", ""),
            ("────────────GRUPOS────────────", ""),
            (" ", ""),
            ("group  <nome> <user1,user2,...>", " Criar grupo de chat"),
            ("delete <nome>", "        Apagar grupo de chat (só o dono)"),
            ("leave  <nome>", "        Sair de grupo de chat"),
            ("groups", "  Listar grupos de chat"),
            ("accept <nome>", "        Aceitar convite para grupo"),
            ("reject <nome>", "        Rejeitar convite para grupo"),
            ("invites", "  Ver convites para grupos de chat"),
            ("invite <grupo> <user>", "           Convidar user para grupo (só o dono)"),
            ("kick   <grupo> <user>", "           Remover user de grupo (só o dono)"),
            (" ", ""),
            ("─────────────SAIR─────────────", ""),
            (" ", ""),
            ("exit", "  Sair da aplicação"),
        ]
        MainPanelView.show_help(cmds)

    def print_chat_message(self, sender: str, recipient: str, text: str, timestamp: str):
        if self._mode == "group":
            GroupPanelView.print_message(sender, recipient, text, timestamp)
        else:
            ChatPanelView.print_message(sender, recipient, text, timestamp)

    def set_username(self, username: str):
        self._username = username

    def set_logged_out(self):
        self._username = None

    def set_mode_main(self):
        self._mode = "main"
        self._target = ""
        self.session.completer = WordCompleter(COMMANDS, ignore_case=True)
        clear()
        self.show_welcome()

    def set_mode_chat(self, target_user: str):
        self._mode = "chat"
        self._target = target_user
        self.session.completer = WordCompleter(["/exit", "/help"], ignore_case=True)
        ChatPanelView.show_header(target_user)

    def set_mode_group(self, target_group: str):
        self._mode = "group"
        self._target = target_group
        self.session.completer = WordCompleter(["/exit", "/help", "/members"], ignore_case=True)
        GroupPanelView.show_header(target_group)

    def _build_prompt(self) -> HTML:
        if not self._username:
            return HTML("<prompt>main ❯ </prompt>")

        username_html = f"<username>{esc(self._username)}</username>"

        if self._mode == "main":
            return HTML(f"<prompt>{username_html} ❯ </prompt>")
        elif self._mode == "chat":
            target_html = f"<info>@{esc(self._target)}</info>"
            return HTML(f"<prompt>{username_html} {target_html} ❯ </prompt>")
        elif self._mode == "group":
            target_html = f"<server>#{esc(self._target)}</server>"
            return HTML(f"<prompt>{username_html} {target_html} ❯ </prompt>")

        return HTML("<prompt>> </prompt>")

    def clear_input_line(self):
        sys.stdout.write("\033[A\033[2K\r")
        sys.stdout.flush()

    async def get_input(self) -> str:
        prompt_text = self._build_prompt()
        with patch_stdout():
            return await self.session.prompt_async(prompt_text)
