import socket
import struct

MAX_MSG_SIZE = 10 * 1024 * 1024


class Transport:
    """TCP transport — usado pelo cliente (connect) e pelo servidor (from_socket)."""

    def __init__(self, sock: socket.socket, addr: tuple):
        self._socket = sock
        self.addr    = addr
        self._buffer = b""

    # ── Construtores ──────────────────────────────────────────────────────────

    @classmethod
    def connect(cls, host: str, port: int) -> "Transport":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        return cls(sock, (host, port))

    @classmethod
    def from_socket(cls, conn: socket.socket, addr: tuple) -> "Transport":
        return cls(conn, addr)

    # ── Interface pública ─────────────────────────────────────────────────────

    @property
    def socket(self) -> socket.socket | None:
        return self._socket

    def send(self, data: bytes) -> None:
        if not self._socket:
            raise OSError("Não ligado.")
        self._socket.sendall(struct.pack(">I", len(data)) + data)

    def recv(self) -> bytes:
        if not self._socket:
            raise OSError("Não ligado.")

        while len(self._buffer) < 4:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise ConnectionResetError("Ligação encerrada pelo par.")
            self._buffer += chunk

        size = struct.unpack(">I", self._buffer[:4])[0]
        if size > MAX_MSG_SIZE:
            raise ValueError(f"Mensagem demasiado grande: {size} bytes")
        self._buffer = self._buffer[4:]

        while len(self._buffer) < size:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise ConnectionResetError("Ligação encerrada pelo par.")
            self._buffer += chunk

        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def disconnect(self) -> None:
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
            self._socket = None
        self._buffer = b""

    # alias usado pelo servidor
    close = disconnect
