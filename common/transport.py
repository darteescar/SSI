import socket
import struct

MAX_MSG_SIZE = 10 * 1024 * 1024


class Transport:
    """Client-side TCP transport — connects to a remote host:port."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket: socket.socket | None = None
        self._buffer = b""

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self._buffer = b""

    def disconnect(self):
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None
        self._buffer = b""

    def send_raw(self, data: bytes):
        if not self.socket:
            raise OSError("Não ligado ao servidor.")
        self.socket.sendall(struct.pack(">I", len(data)) + data)

    def recv_raw(self) -> bytes:
        if not self.socket:
            raise OSError("Não ligado ao servidor.")

        while len(self._buffer) < 4:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise ConnectionResetError("Servidor desligou.")
            self._buffer += chunk

        size = struct.unpack(">I", self._buffer[:4])[0]
        if size > MAX_MSG_SIZE:
            raise ValueError(f"Mensagem demasiado grande: {size} bytes")
        self._buffer = self._buffer[4:]

        while len(self._buffer) < size:
            chunk = self.socket.recv(4096)
            if not chunk:
                raise ConnectionResetError("Servidor desligou.")
            self._buffer += chunk

        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data


class SocketTransport:
    def __init__(self, conn: socket.socket, addr: tuple):
        self.addr = addr
        self._conn = conn
        self._buffer = b""

    def send(self, data: bytes) -> None:
        self._conn.sendall(struct.pack(">I", len(data)) + data)

    def recv(self) -> bytes:
        while len(self._buffer) < 4:
            chunk = self._conn.recv(4096)
            if not chunk:
                raise ConnectionResetError("Cliente desligou.")
            self._buffer += chunk

        size = struct.unpack(">I", self._buffer[:4])[0]
        if size > MAX_MSG_SIZE:
            raise ValueError(f"Mensagem demasiado grande: {size} bytes")
        self._buffer = self._buffer[4:]

        while len(self._buffer) < size:
            chunk = self._conn.recv(4096)
            if not chunk:
                raise ConnectionResetError("Cliente desligou.")
            self._buffer += chunk

        data, self._buffer = self._buffer[:size], self._buffer[size:]
        return data

    def close(self) -> None:
        try:
            self._conn.close()
        except OSError:
            pass
