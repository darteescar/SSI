"""ClientSession — orquestra o ciclo de vida de uma ligação de cliente.

Fases:
  1. Handshake DH         (delegado a SecureChannel.dh_handshake)
  2. Autenticação         (registo / login — sequencial, pré-pool)
  3. Sessão autenticada   (ClientConnection: writer + reader + thread pool)

A sessão NÃO cifra nem toca no socket diretamente: na fase pré-login usa
_send_plain/_recv_plain (uma única thread, sem concorrência); após o login
delega tudo à ClientConnection. send() e push_to_client() — a interface que
os handlers usam — escrevem sempre via a fila da ClientConnection.
"""

import os
import sys
import base64

_SERVER_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PROJECT_DIR = os.path.dirname(_SERVER_DIR)
sys.path.insert(0, _SERVER_DIR)
sys.path.insert(0, _PROJECT_DIR)

import logging
from common.transport import Transport
from net.secure_channel import SecureChannel
from net.connection import ClientConnection
from common import crypto
from common.Message import Message
from common.MsgType import MsgType

_auth    = logging.getLogger("auth")
_e2e     = logging.getLogger("e2e")
_group   = logging.getLogger("group")
_session = logging.getLogger("session")


class ClientSession:
    def __init__(self, conn, addr, user_manager, server_privkey, server_cert, pool):
        self.addr            = addr
        self._server_privkey = server_privkey
        self._server_cert    = server_cert
        self._user_manager   = user_manager
        self._pool           = pool

        transport     = Transport.from_socket(conn, addr)
        self._channel = SecureChannel(transport)

        self.username: str | None = None
        self._connection: ClientConnection | None = None
        self._preauth_rid: str | None = None  # _rid do pedido pré-login em curso

    # ── Interface usada pelos handlers ────────────────────────────────────────

    def send(self, msg: Message) -> None:
        """Resposta ao próprio cliente. Pré-login: escreve já; pós-login: enfileira
        via reply() para ecoar o msg_id do pedido em curso."""
        if self._connection is not None:
            self._connection.reply(msg)
        else:
            self._send_plain(msg)

    def push_to_client(self, msg: Message) -> None:
        """Push vindo de outro cliente. Só faz sentido pós-login."""
        if self._connection is not None:
            self._connection.push_send(msg)

    # ── Envio/recepção sequencial (fase pré-login, sem threads) ───────────────

    def _send_plain(self, msg: Message) -> None:
        # Ecoa o _rid do pedido pré-login para o cliente fazer match no request()
        if self._preauth_rid is not None:
            msg.set("_rid", self._preauth_rid)
        self._channel.send_raw(self._channel.encrypt(msg.serialize().encode("utf-8")))

    def _recv_plain(self) -> Message:
        msg = self._channel.decrypt(self._channel.recv_raw())
        self._preauth_rid = msg.get("_rid")
        return msg

    # ── Fase 1: handshake ─────────────────────────────────────────────────────

    def _phase_dh_handshake(self) -> bool:
        try:
            self._channel.dh_handshake(self._server_privkey)
            print(f"[DH] handshake OK com {self.addr}")
            return True
        except Exception as e:
            _session.error(f"handshake STS falhou com {self.addr}: {e}")
            print(f"[!] DH falhou: {e}")
            return False

    # ── Fase 2: autenticação ──────────────────────────────────────────────────

    def _handle_registo(self, msg: Message) -> bool:
        username          = msg.username
        password          = msg.get("password")
        client_pubkey_pem = msg.get("public_key")
        sig_b64           = msg.get("signature")

        if not all([username, password, client_pubkey_pem, sig_b64]):
            _auth.warning(f"registo de '{username}' rejeitado: payload incompleto ({self.addr})")
            self._send_plain(Message.error("Payload de registo incompleto."))
            return False

        try:
            client_pubkey = crypto.rsa_load_public(client_pubkey_pem.encode())
        except Exception as e:
            _auth.error(f"registo de '{username}' rejeitado: chave pública RSA inválida ({e})")
            self._send_plain(Message.error("Chave pública inválida."))
            return False

        try:
            sig_bytes = base64.b64decode(sig_b64)
            crypto.rsa_verify(client_pubkey, sig_bytes,
                              self._channel.gx_bytes + self._channel.gy_bytes + client_pubkey_pem.encode())
            _auth.info(f"registo de '{username}': proof-of-possession (assinatura sobre g^x||g^y||pubkey) verificado com sucesso")
            print(f"[REGISTO] proof-of-possession de '{username}' verificado OK")
        except Exception as e:
            _auth.warning(f"registo de '{username}' rejeitado: proof-of-possession inválido — possível tentativa de fraude ({e})")
            print(f"[REGISTO] proof-of-possession INVÁLIDO para '{username}'")
            self._send_plain(Message.error("Proof-of-possession inválido."))
            return False

        if self._user_manager.exists(username):
            _auth.warning(f"registo de '{username}' rejeitado: username já existe")
            self._send_plain(Message.error(f"'{username}' já existe."))
            return False

        salt_b64, hash_b64 = crypto.hash_password(password)
        cert_pem = crypto.cert_issue(
            self._server_privkey, username, client_pubkey_pem.encode()
        )
        user_id = self._user_manager.registar(username, salt_b64, hash_b64,
                                               client_pubkey_pem, cert_pem.decode())
        if user_id is None:
            _auth.error(f"registo de '{username}' falhou: erro interno ao persistir conta")
            self._send_plain(Message.error("Erro interno ao registar."))
            return False

        self._send_plain(Message.resp_registo(username, cert_pem.decode(), user_id))
        _auth.info(f"registo de '{username}' concluído — certificado X.509 emitido pelo servidor-CA, password persistida com PBKDF2-HMAC-SHA256+salt, user_id={user_id}")
        print(f"[+] '{username}' registado ({self.addr})")
        return True

    def _reject(self, reason: str):
        self._send_plain(Message.error(reason))
        _auth.warning(f"login rejeitado: {reason}")
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
            _auth.warning(f"login de '{username}' rejeitado: password incorreta (PBKDF2 não corresponde ao hash armazenado)")
            return self._reject("Password incorreta.")

        client_cert_pem = self._user_manager.get_user_cert(username)
        if not client_cert_pem:
            return self._reject("Certificado não encontrado.")

        client_pubkey = crypto.cert_get_public_key(
            crypto.cert_load_bytes(client_cert_pem.encode())
        )
        try:
            sig_bytes = base64.b64decode(sig_b64)
            crypto.rsa_verify(client_pubkey, sig_bytes,
                              self._channel.gx_bytes + self._channel.gy_bytes)
            _auth.info(f"login de '{username}': assinatura STS sobre g^x||g^y verificada com a chave do certificado X.509")
            print(f"[LOGIN] assinatura STS de '{username}' verificada OK")
        except Exception as e:
            _auth.warning(f"login de '{username}' rejeitado: assinatura STS inválida ({e})")
            print(f"[LOGIN] assinatura INVÁLIDA para '{username}'")
            return self._reject("Assinatura inválida.")

        self.username = username

        from app.ClientHandler import ClientHandler
        handler = ClientHandler(self, username, self._user_manager)
        self._user_manager.set_online(username, handler)
        user_id = self._user_manager.get_user_id(username) or 0
        self._send_plain(Message.resp_login(username, user_id))
        _auth.info(f"login concluído via STS (user_id={user_id}) — canal cifrado pronto")
        print(f"[+] '{username}' autenticado")

        # A resp_login já foi enviada com o _rid; os pushes offline a seguir são
        # mensagens não-solicitadas e não devem ecoar nenhum _rid.
        self._preauth_rid = None
        self._flush_offline(username)
        return handler

    def _flush_offline(self, username: str) -> None:
        """Entrega notificações de grupo e mensagens E2E acumuladas offline."""
        notifs = self._user_manager.flush_group_notifications(username)
        if notifs:
            _group.info(f"a entregar {len(notifs)} notificação(ões) de grupo pendente(s) acumuladas enquanto estava offline")
        for n in notifs:
            try:
                if n["type"] == "GROUP_MEMBER_LEFT":
                    self._send_plain(Message.push_group_member_left(n["group_name"], n["info"]))
                    _group.info(f"entregue notificação offline: '{n['info']}' saiu/foi expulso do grupo '{n['group_name']}' — cliente deve rodar a sua sender key")
                elif n["type"] == "GROUP_MEMBER_JOINED":
                    self._send_plain(Message.push_group_member_joined(n["group_name"], n["info"]))
                    _group.info(f"entregue notificação offline: '{n['info']}' entrou no grupo '{n['group_name']}' — cliente deve distribuir-lhe a sua sender key")
            except Exception as e:
                _group.error(f"erro ao entregar notificação offline de grupo: {e}")
                break

        pending = self._user_manager.flush_e2e_queue(username)
        if pending:
            _e2e.info(f"a entregar {len(pending)} mensagem(ns) E2E acumuladas enquanto estava offline (inclui distribuições de sender key e mensagens par-a-par)")
        for queued in pending:
            try:
                _e2e.info(f"entregue blob E2E offline de '{queued['from_']}' (msg_id={queued['msg_id']}, {len(queued['payload'])}B cifrado)")
                self._send_plain(Message.push_e2e_deliver(
                    queued["from_"], queued["msg_id"], queued["payload"]
                ))
            except Exception as e:
                _e2e.error(f"erro ao entregar mensagem E2E offline: {e}")
                break

    # ── Fase 3: sessão autenticada (writer + reader + pool) ───────────────────

    def _eof(self) -> None:
        """Callback chamado pela ClientConnection quando o cliente desliga."""
        pass  # a limpeza é feita no finally de run()

    def run(self) -> None:
        try:
            if not self._phase_dh_handshake():
                return

            handler = None
            while handler is None:
                try:
                    msg = self._recv_plain()
                except Exception:
                    return

                if msg.type == MsgType.REGISTO:
                    self._handle_registo(msg)
                elif msg.type == MsgType.LOGIN:
                    handler = self._handle_login(msg)
                    if handler is None:
                        return
                else:
                    self._send_plain(Message.error(
                        f"Esperado REGISTO ou LOGIN, recebido: {msg.type}"))
                    return

            # Login OK — arranca writer + reader; os pedidos correm no pool.
            self._connection = ClientConnection(
                self._channel, self._pool,
                on_message=handler.handle_message,
                on_eof=self._eof,
            )
            self._connection.start()
            self._connection.join()  # bloqueia até o cliente desligar

        except (ConnectionResetError, ConnectionAbortedError, OSError) as e:
            if self.username:
                print(f"[!] Ligação perdida com '{self.username}': {e}")
        finally:
            if self._connection:
                self._connection.close()
            if self.username:
                self._user_manager.desautenticar(self.username)
                print(f"[-] '{self.username}' desligou-se.")
            self._channel.close()
