import logging
from common.Message import Message
from common.MsgType import MsgType

_log = logging.getLogger("e2e")


class PrekeysHandlerMixin:
    def handle_PREKEY_UPLOAD(self, msg: Message) -> None:
        prekeys = msg.prekeys
        if not isinstance(prekeys, list) or not prekeys:
            self._session.send(Message.error("Payload inválido para PREKEY_UPLOAD."))
            return
        self.user_manager.store_prekeys(self.username, prekeys)
        stock = self.user_manager.prekey_count(self.username)
        _log.info(f"upload de {len(prekeys)} prekeys DH assinadas (X3DH-like, para iniciação offline) — stock total disponível para outros utilizadores: {stock}")
        self._session.send(Message(MsgType.OK, {"info": f"{len(prekeys)} prekeys adicionadas ao stock."}))

    def handle_PREKEY_REQUEST(self, msg: Message) -> None:
        target = msg.info
        if not target:
            self._session.send(Message.error("Payload inválido para PREKEY_REQUEST."))
            return
        if not self.user_manager.exists(target):
            self._session.send(Message.error(f"Utilizador '{target}' não encontrado."))
            return

        cert_pem = self.user_manager.get_user_cert(target) or ""

        if self.user_manager.is_online(target):
            _log.info(f"pediu material para estabelecer E2E com '{target}': destinatário online, devolvido apenas o certificado X.509 (handshake DH direto, sem consumir prekey)")
            self._session.send(Message.resp_online_bundle(cert_pem))
            return

        prekey, low_stock = self.user_manager.pop_prekey(target)
        if prekey is None:
            _log.warning(f"pediu prekey de '{target}' para iniciação offline: stock de prekeys esgotado — sessão E2E não pode ser estabelecida")
            self._session.send(Message.error(
                f"'{target}' está offline e não tem prekeys disponíveis. "
                "Tenta quando estiver online."))
            return

        stock_restante = self.user_manager.prekey_count(target)
        _log.info(
            f"pediu prekey de '{target}' para iniciação X3DH offline — entregue prekey_idx={prekey['idx']}, "
            f"stock restante: {stock_restante}"
            + (" [STOCK BAIXO — cliente vai repor prekeys]" if low_stock else "")
        )
        self._session.send(Message.resp_prekey_bundle(
            prekey_idx=prekey["idx"],
            prekey_pub=prekey["pub"],
            prekey_sig=prekey["sig"],
            cert_pem=cert_pem,
            low_stock=low_stock,
        ))

    def handle_CERT_REQUEST(self, msg: Message) -> None:
        target = msg.info
        if not target:
            self._session.send(Message.error("Payload inválido para CERT_REQUEST."))
            return
        if not self.user_manager.exists(target):
            self._session.send(Message.error(f"Utilizador '{target}' não encontrado."))
            return
        cert_pem = self.user_manager.get_user_cert(target) or ""
        self._session.send(Message.resp_cert(target, cert_pem))

    def handle_E2E_MSG(self, msg: Message) -> None:
        to          = msg.to
        msg_id      = msg.e2e_msg_id
        payload_b64 = msg.payload_b64

        if not to or not msg_id or not payload_b64:
            self._session.send(Message.error("Payload inválido para E2E_MSG."))
            return
        if not self.user_manager.exists(to):
            self._session.send(Message.error(f"Utilizador '{to}' não encontrado."))
            return

        self._session.send(Message(MsgType.OK, {"msg_id": msg_id}))

        deliver = Message.push_e2e_deliver(self.username, msg_id, payload_b64)
        handler = self.user_manager.get_handler(to)
        if handler:
            handler.push_to_client(deliver)
            _log.info(f"relay E2E para '{to}' — payload opaco de {len(payload_b64)}B entregue imediatamente (destinatário online)")
        else:
            self.user_manager.enqueue_e2e_msg(to, self.username, msg_id, payload_b64)
            _log.info(f"relay E2E para '{to}' — payload opaco de {len(payload_b64)}B enfileirado em disco (destinatário offline, entrega no próximo login)")

    def handle_E2E_ACK(self, msg: Message) -> None:
        msg_id = msg.e2e_msg_id
        if msg_id:
            self.user_manager.remove_e2e_msg(self.username, msg_id)
