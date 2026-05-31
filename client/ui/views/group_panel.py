from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import clear
from .base import STYLE, esc

class GroupPanelView:
    @staticmethod
    def show_header(target_group: str):
        clear()
        print_formatted_text(HTML(f"\n<prompt>╭────────────────────────────────────────╮</prompt>"), style=STYLE)
        print_formatted_text(HTML(f"<prompt>│  Grupo: <server>#{esc(target_group).ljust(29)}</server>│</prompt>"), style=STYLE)
        print_formatted_text(HTML(f"<prompt>╰────────────────────────────────────────╯</prompt>\n"), style=STYLE)

    @staticmethod
    def print_message(sender: str, group: str, text: str, timestamp: str):
        print_formatted_text(HTML(
            f"<chat><username>{esc(sender)}</username> → <server>{esc(group)}</server> "
            f"<timestamp>{timestamp}</timestamp>: {esc(text)}</chat>"
        ), style=STYLE)
