from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from .base import STYLE, esc, print_info, print_separator

class MainPanelView:
    @staticmethod
    def print_contacts(contacts: list[str]):
        print_separator()
        if not contacts:
            print_info("Sem contactos. Use 'add <username>'")
        else:
            for contact in contacts:
                print_formatted_text(HTML(f"  👤 <username>{esc(contact)}</username>"), style=STYLE)
        print_separator()

    @staticmethod
    def print_invites(invites: list[dict]):
        print_separator()
        if not invites:
            print_info("Sem convites pendentes.")
        else:
            for invite in invites:
                group  = invite.get("group_name", "??")
                sender = invite.get("from_name",  "??")
                ts     = invite.get("timestamp",  "")
                print_formatted_text(HTML(
                    f" 👥 <username>[{ts}]</username> Convite para o grupo <server>{esc(group)}</server> enviado por <username>{esc(sender)}</username>"
                ), style=STYLE)
        print_separator()

    @staticmethod
    def print_online(users: list[str]):
        print_separator()
        if not users:
            print_info("Ninguém online.")
        else:
            for user in users:
                print_formatted_text(HTML(f"  🌐 <username>{esc(user)}</username>"), style=STYLE)
        print_separator()

    @staticmethod
    def print_groups(groups: dict[str, list[str]]):
        print_separator()
        if not groups:
            print_info("Sem grupos de chat.")
        else:
            for name, members in groups.items():
                members_str = ", ".join(members) if members else "—"
                print_formatted_text(HTML(
                    f"  👥 <username>{esc(name)}</username>  <info>{esc(members_str)}</info>"
                ), style=STYLE)
        print_separator()

    @staticmethod
    def show_welcome():
        print_formatted_text(HTML("\n<prompt>╔═══════════════════════════════════╗</prompt>"), style=STYLE)
        print_formatted_text(HTML("<prompt>║    Chat E2EE — Cliente          ║</prompt>"), style=STYLE)
        print_formatted_text(HTML("<prompt>╚═══════════════════════════════════╝</prompt>"), style=STYLE)
        print_info("Escreva 'help' para ver os comandos disponíveis.\n")

    @staticmethod
    def show_help(cmds: list[tuple[str, str]]):
        print_separator()
        for cmd, desc in cmds:
            cmd_escaped = esc(cmd)
            cmd_padded = cmd_escaped.ljust(30)
            print_formatted_text(HTML(f"  <cmd>{cmd_padded}</cmd> {desc}"), style=STYLE)
        print_separator()
