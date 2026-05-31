from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ClientHandler import ClientHandler


class UserManagerMixin:
    def registar(self, username: str, salt_b64: str, hash_b64: str,
                 pubkey_pem: str, cert_pem: str) -> int | None:
        with self.lock:
            if username in self.username_to_id:
                return None
            user_id = self.next_user_id
            self.next_user_id += 1
            self.users[user_id] = {
                "username":    username,
                "salt":        salt_b64,
                "hash":        hash_b64,
                "public_key":  pubkey_pem,
                "certificate": cert_pem,
            }
            self.username_to_id[username] = user_id
            self._save_users()
            return user_id

    def apagar(self, username: str) -> bool:
        with self.lock:
            user_id = self.username_to_id.pop(username, None)
            if user_id is None:
                return False
            self.users.pop(user_id, None)
            self._save_users()
            return True

    def exists(self, username: str) -> bool:
        with self.lock:
            return username in self.username_to_id

    def get_user_id(self, username: str) -> int | None:
        with self.lock:
            return self.username_to_id.get(username)

    def set_online(self, username: str, handler: "ClientHandler") -> bool:
        with self.lock:
            user_id = self.username_to_id.get(username)
            if user_id is None:
                return False
            self.users_online[user_id] = handler
            return True

    def desautenticar(self, username: str):
        with self.lock:
            user_id = self.username_to_id.get(username)
            if user_id is not None:
                self.users_online.pop(user_id, None)

    def is_online(self, username: str) -> bool:
        with self.lock:
            user_id = self.username_to_id.get(username)
            return user_id in self.users_online if user_id is not None else False

    def list_online(self) -> list[str]:
        with self.lock:
            return [
                self.users[uid]["username"]
                for uid in self.users_online
                if uid in self.users
            ]

    def get_handler(self, username: str) -> "ClientHandler | None":
        with self.lock:
            user_id = self.username_to_id.get(username)
            return self.users_online.get(user_id) if user_id is not None else None

    def get_user_cert(self, username: str) -> str | None:
        with self.lock:
            user_id = self.username_to_id.get(username)
            if user_id is None:
                return None
            entry = self.users.get(user_id)
            return entry.get("certificate") if entry else None

    def get_user_salt_hash(self, username: str) -> tuple[str, str] | None:
        with self.lock:
            user_id = self.username_to_id.get(username)
            if user_id is None:
                return None
            entry = self.users.get(user_id)
            if not entry:
                return None
            return entry.get("salt"), entry.get("hash")

    def get_user_pubkey(self, username: str) -> str | None:
        with self.lock:
            user_id = self.username_to_id.get(username)
            if user_id is None:
                return None
            entry = self.users.get(user_id)
            return entry.get("public_key") if entry else None
