import json
import os

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

USERS_FILE       = os.path.join(_SERVER_DIR, "db", "users.json")
CONTACTS_FILE    = os.path.join(_SERVER_DIR, "db", "contacts.json")
GROUPS_FILE      = os.path.join(_SERVER_DIR, "db", "groups.json")
INVITES_FILE     = os.path.join(_SERVER_DIR, "db", "invites.json")
CHATS_FILE       = os.path.join(_SERVER_DIR, "db", "chats.json")
GROUP_MSGS_FILE  = os.path.join(_SERVER_DIR, "db", "group_messages.json")
PREKEYS_FILE     = os.path.join(_SERVER_DIR, "db", "prekeys.json")
E2E_QUEUE_FILE   = os.path.join(_SERVER_DIR, "db", "e2e_queue.json")
GROUP_NOTIF_FILE = os.path.join(_SERVER_DIR, "db", "group_notifications.json")


class PersistenceManager:

    def load_users(self) -> dict:
        return self.load(USERS_FILE, default={"next_id": 1})

    def save_users(self, users: dict):
        self.save(USERS_FILE, users)

    def load_contacts(self) -> dict:
        return self.load(CONTACTS_FILE, default={})

    def save_contacts(self, contacts: dict):
        self.save(CONTACTS_FILE, contacts)

    def load_groups(self) -> dict:
        return self.load(GROUPS_FILE, default={"next_id": 1})

    def save_groups(self, groups: dict):
        self.save(GROUPS_FILE, groups)

    def load_invites(self) -> dict:
        return self.load(INVITES_FILE, default={})

    def save_invites(self, invites: dict):
        self.save(INVITES_FILE, invites)

    def load_chats(self) -> dict:
        return self.load(CHATS_FILE, default={})

    def save_chats(self, chats: dict):
        self.save(CHATS_FILE, chats)

    def load_group_messages(self) -> dict:
        return self.load(GROUP_MSGS_FILE, default={})

    def save_group_messages(self, data: dict):
        self.save(GROUP_MSGS_FILE, data)

    def load_prekeys(self) -> dict:
        return self.load(PREKEYS_FILE, default={})

    def save_prekeys(self, data: dict):
        self.save(PREKEYS_FILE, data)

    def load_e2e_queue(self) -> dict:
        return self.load(E2E_QUEUE_FILE, default={})

    def save_e2e_queue(self, data: dict):
        self.save(E2E_QUEUE_FILE, data)

    def load_group_notifications(self) -> dict:
        return self.load(GROUP_NOTIF_FILE, default={})

    def save_group_notifications(self, data: dict):
        self.save(GROUP_NOTIF_FILE, data)

    def load(self, path: str, default):
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return default

    def save(self, path: str, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
        except OSError as e:
            print(f"[!] Erro ao guardar '{path}': {e}")
