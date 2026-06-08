import socket
import threading
import sys
import os
from concurrent.futures import ThreadPoolExecutor

_SERVER_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SERVER_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common import crypto
from app.ServerManager import ServerManager
from app.session import ClientSession

HOST = "127.0.0.1"
PORT = 6767

CA_DIR      = os.path.join(_SERVER_DIR, "ca")
POOL_WORKERS = 16   # threads partilhadas para executar pedidos de todos os clientes


class Server:
    def __init__(self):
        if not os.path.exists(os.path.join(CA_DIR, "server.key")):
            print("[*] Credenciais do servidor não encontradas — a gerar...")
            crypto.cert_setup_server(CA_DIR)

        self.server_privkey, self.server_cert = crypto.cert_load_server(CA_DIR)
        print(f"[+] Credenciais do servidor carregadas de {CA_DIR}")

        self.user_manager = ServerManager()
        self.pool = ThreadPoolExecutor(max_workers=POOL_WORKERS, thread_name_prefix="ReqPool")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((HOST, PORT))
        self.server_socket.listen()
        print(f"[*] Servidor à escuta em {HOST}:{PORT}")

    def start(self):
        try:
            while True:
                conn, addr = self.server_socket.accept()
                print(f"[*] Nova conexão de {addr}")
                session = ClientSession(
                    conn, addr,
                    self.user_manager,
                    self.server_privkey,
                    self.server_cert,
                    self.pool,
                )
                threading.Thread(target=session.run, daemon=True).start()
        except KeyboardInterrupt:
            print("\n[*] Servidor encerrado")
        finally:
            self.server_socket.close()
            self.pool.shutdown(wait=False)


if __name__ == "__main__":
    try:
        Server().start()
    except Exception as e:
        print(f"[!] Erro ao iniciar servidor: {e}")
        sys.exit(1)
