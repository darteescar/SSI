PREKEY_LOW_STOCK = 5


class PrekeysManagerMixin:
    def store_prekeys(self, username: str, prekeys: list[dict]) -> None:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return
            pk = self.db.load_prekeys()
            key = str(uid)
            pk.setdefault(key, []).extend(prekeys)
            self.db.save_prekeys(pk)

    def pop_prekey(self, username: str) -> tuple[dict | None, bool]:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return None, False
            pk  = self.db.load_prekeys()
            key = str(uid)
            prekeys = pk.get(key, [])
            if not prekeys:
                return None, True
            prekey = prekeys.pop(0)
            pk[key] = prekeys
            self.db.save_prekeys(pk)
            low_stock = len(prekeys) <= PREKEY_LOW_STOCK
            return prekey, low_stock

    def prekey_count(self, username: str) -> int:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return 0
            pk = self.db.load_prekeys()
            return len(pk.get(str(uid), []))

    def enqueue_e2e_msg(self, to_username: str, from_username: str,
                        msg_id: str, payload_b64: str) -> None:
        with self.lock:
            to_uid = self.username_to_id.get(to_username)
            if to_uid is None:
                return
            q   = self.db.load_e2e_queue()
            key = str(to_uid)
            q.setdefault(key, []).append({
                "from_":   from_username,
                "msg_id":  msg_id,
                "payload": payload_b64,
            })
            self.db.save_e2e_queue(q)

    def flush_e2e_queue(self, username: str) -> list[dict]:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return []
            q   = self.db.load_e2e_queue()
            key = str(uid)
            msgs = q.pop(key, [])
            if msgs:
                self.db.save_e2e_queue(q)
            return msgs

    def remove_e2e_msg(self, username: str, msg_id: str) -> None:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return
            q   = self.db.load_e2e_queue()
            key = str(uid)
            q[key] = [m for m in q.get(key, []) if m["msg_id"] != msg_id]
            self.db.save_e2e_queue(q)

    def enqueue_group_notification(self, to_username: str, msg_type: str,
                                   group_name: str, info: str) -> None:
        with self.lock:
            to_uid = self.username_to_id.get(to_username)
            if to_uid is None:
                return
            q   = self.db.load_group_notifications()
            key = str(to_uid)
            q.setdefault(key, []).append({
                "type":       msg_type,
                "group_name": group_name,
                "info":       info,
            })
            self.db.save_group_notifications(q)

    def flush_group_notifications(self, username: str) -> list[dict]:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return []
            q   = self.db.load_group_notifications()
            key = str(uid)
            msgs = q.pop(key, [])
            if msgs:
                self.db.save_group_notifications(q)
            return msgs
