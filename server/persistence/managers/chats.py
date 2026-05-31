from common.Message import Message


class ChatManagerMixin:

    def set_online_chat(self, user1: str, user2: str, is_online: bool = True):
        with self.lock:
            uid1 = self.username_to_id.get(user1)
            uid2 = self.username_to_id.get(user2)
            if uid1 is None or uid2 is None:
                return
            u_min, u_max = min(uid1, uid2), max(uid1, uid2)
            chat_key     = f"{u_min}_{u_max}"
            estado_atual = self.chats_online.get(chat_key, (False, False))
            if uid1 == u_min:
                self.chats_online[chat_key] = (is_online, estado_atual[1])
            else:
                self.chats_online[chat_key] = (estado_atual[0], is_online)

    def is_the_other_online_in_chat(self, user1: str, user2: str) -> bool:
        with self.lock:
            uid1 = self.username_to_id.get(user1)
            uid2 = self.username_to_id.get(user2)
            if uid1 is None or uid2 is None:
                return False
            u_min, u_max = min(uid1, uid2), max(uid1, uid2)
            chat_key     = f"{u_min}_{u_max}"
            estado = self.chats_online.get(chat_key, (False, False))
            return estado[1] if uid1 == u_min else estado[0]

    def get_chat_history(self, user1: str, user2: str) -> list[dict]:
        with self.lock:
            uid1 = self.username_to_id.get(user1)
            uid2 = self.username_to_id.get(user2)
            if uid1 is None or uid2 is None:
                return []
            chat_key = f"{min(uid1, uid2)}_{max(uid1, uid2)}"
            chats    = self.db.load_chats()
            result   = []
            for m in chats.get(chat_key, []):
                from_entry = self.users.get(m["from_id"])
                to_entry   = self.users.get(m["to_id"])
                result.append({
                    "from_":     from_entry["username"] if from_entry else "?",
                    "to":        to_entry["username"]   if to_entry   else "?",
                    "text":      m["text"],
                    "timestamp": m["timestamp"],
                })
            return result

    def save_chat_message(self, msg: Message):
        with self.lock:
            sender_id    = self.username_to_id.get(msg.from_)
            recipient_id = self.username_to_id.get(msg.to)
            if sender_id is None or recipient_id is None:
                return
            chat_key = f"{min(sender_id, recipient_id)}_{max(sender_id, recipient_id)}"
            chats    = self.db.load_chats()
            chats.setdefault(chat_key, []).append({
                "from_id":   sender_id,
                "to_id":     recipient_id,
                "text":      msg.text,
                "timestamp": msg.timestamp,
            })
            self.db.save_chats(chats)

    def open_group_chat(self, username: str, group_name: str) -> list[dict]:
        with self.lock:
            uid = self.username_to_id.get(username)
            gid = self.groupname_to_id.get(group_name)
            if uid is None or gid is None:
                return []
            self.group_chats_online.setdefault(gid, set()).add(uid)
            gm      = self.db.load_group_messages()
            key     = str(gid)
            gdata   = gm.get(key, {"next_msg_id": 1, "messages": []})
            result  = []
            changed = False
            for m in gdata["messages"]:
                if uid not in m["pending_acks"]:
                    continue
                from_entry = self.users.get(m["from_id"])
                result.append({
                    "msg_id":    m["msg_id"],
                    "from_":     from_entry["username"] if from_entry else "?",
                    "to":        group_name,
                    "payload":   m["payload"],
                    "timestamp": m["timestamp"],
                })
                m["pending_acks"].remove(uid)
                changed = True
            if changed:
                gdata["messages"] = [m for m in gdata["messages"] if m["pending_acks"]]
                gm[key] = gdata
                self.db.save_group_messages(gm)
            return result

    def leave_group_chat(self, username: str, group_name: str):
        with self.lock:
            uid = self.username_to_id.get(username)
            gid = self.groupname_to_id.get(group_name)
            if uid is None or gid is None:
                return
            self.group_chats_online.get(gid, set()).discard(uid)

    def save_group_message(self, group_name: str, from_username: str,
                           payload: str, timestamp: str) -> int | None:
        with self.lock:
            gid = self.groupname_to_id.get(group_name)
            uid = self.username_to_id.get(from_username)
            if gid is None or uid is None:
                return None
            group = self.groups.get(gid)
            if group is None:
                return None
            pending = [mid for mid in group["members"] if mid != uid]
            gm  = self.db.load_group_messages()
            key = str(gid)
            if key not in gm:
                gm[key] = {"next_msg_id": 1, "messages": []}
            msg_id = gm[key]["next_msg_id"]
            gm[key]["next_msg_id"] += 1
            gm[key]["messages"].append({
                "msg_id":       msg_id,
                "from_id":      uid,
                "payload":      payload,
                "timestamp":    timestamp,
                "pending_acks": pending,
            })
            self.db.save_group_messages(gm)
            return msg_id

    def ack_group_message(self, group_name: str, msg_id: int, username: str):
        with self.lock:
            uid = self.username_to_id.get(username)
            gid = self.groupname_to_id.get(group_name)
            if uid is None or gid is None:
                return
            gm  = self.db.load_group_messages()
            key = str(gid)
            if key not in gm:
                return
            messages = gm[key]["messages"]
            for m in messages:
                if m["msg_id"] == msg_id and uid in m["pending_acks"]:
                    m["pending_acks"].remove(uid)
                    break
            gm[key]["messages"] = [m for m in messages if m["pending_acks"]]
            self.db.save_group_messages(gm)

    def get_group_online_handlers(self, group_name: str, exclude_username: str) -> list:
        with self.lock:
            gid         = self.groupname_to_id.get(group_name)
            exclude_uid = self.username_to_id.get(exclude_username)
            if gid is None:
                return []
            group = self.groups.get(gid, {})
            return [
                handler
                for uid in group.get("members", [])
                if uid != exclude_uid
                and (handler := self.users_online.get(uid)) is not None
            ]
