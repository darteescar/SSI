from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.shortcuts import clear
from .base import STYLE, esc

class ChatPanelView:
    @staticmethod
    def show_header(target_user: str):
        clear()
        print_formatted_text(HTML(f"\n<prompt>╭────────────────────────────────────────╮</prompt>"), style=STYLE)
        print_formatted_text(HTML(f"<prompt>│  Chat com: <info>@{esc(target_user).ljust(26)}</info>│</prompt>"), style=STYLE)
        print_formatted_text(HTML(f"<prompt>╰────────────────────────────────────────╯</prompt>\n"), style=STYLE)

    @staticmethod
    def print_message(sender: str, recipient: str, text: str, timestamp: str):
        print_formatted_text(HTML(f"<chat><b>{esc(sender)}</b> → <b>{esc(recipient)}</b> "
                                  f"<timestamp>{timestamp}</timestamp>: {esc(text)}</chat>"), style=STYLE)
