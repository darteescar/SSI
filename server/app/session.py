import os
import sys
import base64
import queue
import threading

_SERVER_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SERVER_DIR)
sys.path.insert(0, _PROJECT_DIR)

from common.transport import SocketTransport
from net.secure_channel import SecureChannel
from common import crypto
from common.Message import Message
from common.MsgType import MsgType
import logger as log


class ClientSession:
    def __init__(self, conn, addr, user_manager, server_privkey, server_cert):
        self.addr            = addr
        self._server_privkey = server_privkey
        self._server_cert    = server_cert
        self._user_manager   = user_manager

        transport     = SocketTransport(conn, addr)
        self._channel = SecureChannel(transport)

        self.username: str | None    = None
        self._gx_bytes: bytes | None = None
        self._gy_bytes: bytes | None = None

        self._queue: queue.Queue[tuple[str, Message | None]] = queue.Queue()
        self._rekey_done: threading.Event = threading.Event()

    def send(self, msg: Message) -> None:
        self._channel.send(msg)

    def push_to_client(self, msg: Message) -> None:
        self._queue.put(("push", msg))

    def _phase_dh_handshake(self) -> bool:
        try:
            gx_bytes = self._channel.recv_raw()

            dh_priv, gy_bytes = crypto.dh_generate_keypair()

            sig_servidor = crypto.rsa_sign(self._server_privkey, gx_bytes + gy_bytes)
            self._channel.send_raw(
                crypto.mkpair(gy_bytes, sig_servidor)
            )

            shared = crypto.dh_compute_shared(dh_priv, gx_bytes)
            self._channel.establish(shared)
            self._gx_bytes = gx_bytes
            self._gy_bytes = gy_bytes
            log.dh.info(f"handshake STS concluído com {self.addr} — segredo partilhado derivado via DH, canal cifrado pronto (AES-256-GCM, chaves via HKDF-SHA256)")
            print(f"[DH] handshake OK com {self.addr}")
            return True

        except Exception as e:
            log.dh.error(f"handshake STS falhou com {self.addr}: {e}")
            print(f"[!] DH falhou: {e}")
            return False

    def _handle_registo(self, msg: Message) -> bool:
        username          = msg.username
        password          = msg.get("password")
        client_pubkey_pem = msg.get("public_key")
        sig_b64           = msg.get("signature")

        if not all([username, password, client_pubkey_pem, sig_b64]):
            log.auth.warning(f"registo de '{username}' rejeitado: payload incompleto ({self.addr})")
            self._channel.send(Message.error("Payload de registo incompleto."))
            return False

        try:
            client_pubkey = crypto.rsa_load_public(client_pubkey_pem.encode())
        except Exception as e:
            log.auth.error(f"registo de '{username}' rejeitado: chave pública RSA inválida ({e})")
            self._channel.send(Message.error("Chave pública inválida."))
            return False

        try:
            sig_bytes = base64.b64decode(sig_b64)
            crypto.rsa_verify(client_pubkey, sig_bytes,
                              self._gx_bytes + self._gy_bytes + client_pubkey_pem.encode())
            log.auth.info(f"registo de '{username}': proof-of-possession (assinatura sobre g^x||g^y||pubkey) verificado com sucesso")
            print(f"[REGISTO] proof-of-possession de '{username}' verificado OK")
        except Exception as e:
            log.auth.warning(f"registo de '{username}' rejeitado: proof-of-possession inválido — possível tentativa de fraude ({e})")
            print(f"[REGISTO] proof-of-possession INVÁLIDO para '{username}'")
            self._channel.send(Message.error("Proof-of-possession inválido."))
            self._gx_bytes = None
            self._gy_bytes = None
            return False

        if self._user_manager.exists(username):
            log.auth.warning(f"registo de '{username}' rejeitado: username já existe")
            self._channel.send(Message.error(f"'{username}' já existe."))
            return False

        salt_b64, hash_b64 = crypto.hash_password(password)
        cert_pem = crypto.cert_issue(
            self._server_privkey, username, client_pubkey_pem.encode()
        )
        user_id = self._user_manager.registar(username, salt_b64, hash_b64,
                                               client_pubkey_pem, cert_pem.decode())
        if user_id is None:
            log.auth.error(f"registo de '{username}' falhou: erro interno ao persistir conta")
            self._channel.send(Message.error("Erro interno ao registar."))
            return False

        self._channel.send(Message.resp_registo(username, cert_pem.decode(), user_id))
        log.auth.info(f"registo de '{username}' concluído — certificado X.509 emitido pelo servidor-CA, password persistida com PBKDF2-HMAC-SHA256+salt, user_id={user_id}")
        print(f"[+] '{username}' registado ({self.addr})")
        return True

    def _reject(self, reason: str):
        self._channel.send(Message.error(reason))
        log.auth.warning(f"login rejeitado: {reason}")
        print(f"[!] Login rejeitado: {reason}")
        return None

    def _handle_login(self, msg: Message):
        username = msg.username
        password = msg.get("password")
        sig_b64  = msg.get("signature")

        if not username or not password or not sig_b64:
            return self._reject("Payload de login incompleto.")
        if not self._user_manager.exists(username):
            return self._reject(f"Utilizador '{username}' não existe.")
        if self._user_manager.is_online(username):
            return self._reject(f"'{username}' já está autenticado.")

        salt_hash = self._user_manager.get_user_salt_hash(username)
        if not salt_hash or not crypto.verify_password(password, salt_hash[0], salt_hash[1]):
            log.auth.warning(f"login de '{username}' rejeitado: password incorreta (PBKDF2 não corresponde ao hash armazenado)")
            return self._reject("Password incorreta.")

        client_cert_pem = self._user_manager.get_user_cert(username)
        if not client_cert_pem:
            return self._reject("Certificado não encontrado.")

        client_pubkey = crypto.cert_get_public_key(
            crypto.cert_load_bytes(client_cert_pem.encode())
        )
        try:
            sig_bytes = base64.b64decode(sig_b64)
            crypto.rsa_verify(client_pubkey, sig_bytes, self._gx_bytes + self._gy_bytes)
            log.auth.info(f"login de '{username}': assinatura STS sobre g^x||g^y verificada com a chave do certificado X.509")
            print(f"[LOGIN] assinatura STS de '{username}' verificada OK")
        except Exception as e:
            log.auth.warning(f"login de '{username}' rejeitado: assinatura STS inválida ({e})")
            print(f"[LOGIN] assinatura INVÁLIDA para '{username}'")
            return self._reject("Assinatura inválida.")

        self._gx_bytes = None
        self._gy_bytes = None
        self.username  = username
        log.set_current_user(username)

        from app.ClientHandler import ClientHandler
        handler = ClientHandler(self, username, self._user_manager)
        self._user_manager.set_online(username, handler)
        user_id = self._user_manager.get_user_id(username) or 0
        self._channel.send(Message.resp_login(username, user_id))
        log.auth.info(f"login concluído via STS (user_id={user_id}) — canal cifrado pronto")
        print(f"[+] '{username}' autenticado")

        notifs = self._user_manager.flush_group_notifications(username)
        if notifs:
            log.group.info(f"a entregar {len(notifs)} notificação(ões) de grupo pendente(s) acumuladas enquanto estava offline")
        for n in notifs:
            try:
                if n["type"] == "GROUP_MEMBER_LEFT":
                    self._channel.send(Message.push_group_member_left(n["group_name"], n["info"]))
                    log.group.info(f"entregue notificação offline: '{n['info']}' saiu/foi expulso do grupo '{n['group_name']}' — cliente deve rodar a sua sender key")
                elif n["type"] == "GROUP_MEMBER_JOINED":
                    self._channel.send(Message.push_group_member_joined(n["group_name"], n["info"]))
                    log.group.info(f"entregue notificação offline: '{n['info']}' entrou no grupo '{n['group_name']}' — cliente deve distribuir-lhe a sua sender key")
            except Exception as e:
                log.group.error(f"erro ao entregar notificação offline de grupo: {e}")
                break

        pending = self._user_manager.flush_e2e_queue(username)
        if pending:
            log.e2e.info(f"a entregar {len(pending)} mensagem(ns) E2E acumuladas enquanto estava offline (inclui distribuições de sender key e mensagens par-a-par)")
        for queued in pending:
            try:
                log.e2e.info(f"entregue blob E2E offline de '{queued['from_']}' (msg_id={queued['msg_id']}, {len(queued['payload'])}B cifrado)")
                self._channel.send(Message.push_e2e_deliver(
                    queued["from_"], queued["msg_id"], queued["payload"]
                ))
            except Exception as e:
                log.e2e.error(f"erro ao entregar mensagem E2E offline: {e}")
                break

        return handler

    def _socket_reader(self) -> None:
        log.set_current_user(self.username)
        while True:
            try:
                msg = self._channel.recv()
            except Exception as e:
                log.session.debug(f"socket fechado pelo cliente ({self.addr}): {e}")
                self._queue.put(("eof", None))
                return

            if msg.type == MsgType.REKEY:
                self._rekey_done.clear()
                self._queue.put(("rekey", msg))
                self._rekey_done.wait()
            else:
                self._queue.put(("client", msg))

    def _phase_main_loop(self, handler) -> None:
        reader = threading.Thread(target=self._socket_reader, daemon=True)
        reader.start()

        try:
            while True:
                tag, msg = self._queue.get()

                if tag == "eof":
                    break

                elif tag == "push":
                    try:
                        self._channel.send(msg)
                    except Exception as e:
                        log.session.error(f"falhou push de '{msg.type}' para o cliente: {e}")
                        break

                elif tag == "rekey":
                    try:
                        new_gx           = base64.b64decode(msg.get("gx"))
                        new_priv, new_gy = crypto.dh_generate_keypair()
                        new_shared       = crypto.dh_compute_shared(new_priv, new_gx)
                        self._channel.send(Message.resp_rekey(new_gy))
                        self._channel.update_epoch(new_shared)
                        log.dh.info("renegociação DH concluída — nova epoch instalada, mensagens seguintes usam chave derivada do novo segredo partilhado")
                    except Exception as e:
                        log.session.error(f"renegociação DH falhou: {e}")
                        break
                    finally:
                        self._rekey_done.set()

                else:  # "client"
                    try:
                        handler.handle_message(msg)
                    except (ConnectionResetError, ConnectionAbortedError):
                        break
                    except Exception as e:
                        log.session.error(f"erro ao processar mensagem {msg.type}: {e}", exc_info=True)
                        print(f"[!] Erro ao processar mensagem de '{self.username}': {e}")
                        break
        finally:
            self._rekey_done.set()

    def run(self) -> None:
        try:
            if not self._phase_dh_handshake():
                return

            handler = None
            while True:
                try:
                    msg = self._channel.recv()
                except Exception:
                    return

                if msg.type == MsgType.REGISTO:
                    self._handle_registo(msg)
                elif msg.type == MsgType.LOGIN:
                    handler = self._handle_login(msg)
                    if handler is None:
                        return
                    break
                else:
                    self._channel.send(Message.error(
                        f"Esperado REGISTO ou LOGIN, recebido: {msg.type}"))
                    return

            self._phase_main_loop(handler)

        except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
            if self.username:
                print(f"[!] Ligação perdida com '{self.username}': {e}")
        finally:
            if self.username:
                self._user_manager.desautenticar(self.username)
                print(f"[-] '{self.username}' desligou-se.")
            self._channel.close()
