from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style

STYLE = Style.from_dict({
    "prompt":    "#00aaff bold",
    "username":  "#00ff88 bold",
    "server":    "#ffaa00 italic",
    "error":     "#ff4444 bold",
    "success":   "#00ff88",
    "info":      "#aaaaaa italic",
    "separator": "#444444",
    "cmd":       "#00ccff",
    "chat":      "#dddddd",
    "timestamp": "#666666 italic",
})

def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def print_error(text: str):
    print_formatted_text(HTML(f"  <error>✗ {esc(text)}</error>"), style=STYLE)

def print_success(text: str):
    print_formatted_text(HTML(f"  <success>✓ {esc(text)}</success>"), style=STYLE)

def print_info(text: str):
    print_formatted_text(HTML(f"  <info>{esc(text)}</info>"), style=STYLE)

def print_separator():
    print_formatted_text(HTML("  <separator>" + "─" * 60 + "</separator>"), style=STYLE)
