"""Logger centralizado do servidor — escreve para server.log e para stdout.

Cada record inclui o nome do utilizador associado ao contexto de execução
(via contextvars), para que se possa identificar quem disparou cada evento.
"""

import contextvars
import logging
import os

_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server.log")

_current_user: contextvars.ContextVar[str] = contextvars.ContextVar("user", default="-")


def set_current_user(username: str | None) -> None:
    _current_user.set(username or "-")


class _UserFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.user = _current_user.get()
        return True


_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)-5s] %(name)-7s user=%(user)-10s — %(message)s",
    datefmt="%H:%M:%S",
)


def _make_logger(name: str) -> logging.Logger:
    log = logging.getLogger(name)
    if log.handlers:
        return log
    log.setLevel(logging.DEBUG)
    fh = logging.FileHandler(_LOG_PATH, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(_fmt)
    fh.addFilter(_UserFilter())
    log.addHandler(fh)
    return log


# Loggers por domínio
dh      = _make_logger("dh")
auth    = _make_logger("auth")
e2e     = _make_logger("e2e")
chat    = _make_logger("chat")
group   = _make_logger("group")
session = _make_logger("session")
