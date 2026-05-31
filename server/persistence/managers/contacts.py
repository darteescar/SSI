class ContactsManagerMixin:
    def add_contact(self, username: str, contact: str) -> bool:
        with self.lock:
            uid = self.username_to_id.get(username)
            cid = self.username_to_id.get(contact)
            if uid is None or cid is None:
                return False
            bucket = self.contacts.setdefault(uid, [])
            if cid in bucket:
                return False
            bucket.append(cid)
            self._save_contacts()
            return True

    def remove_contact(self, username: str, contact: str) -> bool:
        with self.lock:
            uid = self.username_to_id.get(username)
            cid = self.username_to_id.get(contact)
            if uid is None or cid is None:
                return False
            bucket = self.contacts.get(uid, [])
            if cid not in bucket:
                return False
            bucket.remove(cid)
            self._save_contacts()
            return True

    def get_contacts(self, username: str) -> list[str]:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return []
            return [
                self.users[cid]["username"]
                for cid in self.contacts.get(uid, [])
                if cid in self.users
            ]

    def has_contact(self, username: str, contact: str) -> bool:
        with self.lock:
            uid = self.username_to_id.get(username)
            cid = self.username_to_id.get(contact)
            if uid is None or cid is None:
                return False
            return cid in self.contacts.get(uid, [])
