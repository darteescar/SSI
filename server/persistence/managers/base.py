import threading
from typing import TYPE_CHECKING
from persistence.managers.persistence import PersistenceManager

if TYPE_CHECKING:
    from app.ClientHandler import ClientHandler


class BaseManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.db   = PersistenceManager()

        users_raw          = self.db.load_users()
        self.next_user_id  = users_raw.pop("next_id", 1)
        self.users: dict[int, dict] = {int(k): v for k, v in users_raw.items()}
        self.username_to_id: dict[str, int] = {
            v["username"]: int(k) for k, v in users_raw.items()
        }

        contacts_raw = self.db.load_contacts()
        self.contacts: dict[int, list[int]] = {int(k): v for k, v in contacts_raw.items()}

        invites_raw = self.db.load_invites()
        self.invites: dict[int, list[dict]] = {int(k): v for k, v in invites_raw.items()}

        groups_raw         = self.db.load_groups()
        self.next_group_id = groups_raw.pop("next_id", 1)
        self.groups: dict[int, dict] = {int(k): v for k, v in groups_raw.items()}
        self.groupname_to_id: dict[str, int] = {
            v["name"]: int(k) for k, v in groups_raw.items()
        }

        self.users_online: dict[int, "ClientHandler"] = {}
        self.chats_online: dict[str, tuple[bool, bool]] = {}
        self.group_chats_online: dict[int, set[int]] = {}

    def _save_users(self):
        data: dict = {"next_id": self.next_user_id}
        data.update({str(k): v for k, v in self.users.items()})
        self.db.save_users(data)

    def _save_contacts(self):
        self.db.save_contacts({str(k): v for k, v in self.contacts.items()})

    def _save_invites(self):
        self.db.save_invites({str(k): v for k, v in self.invites.items()})

    def _save_groups(self):
        data: dict = {"next_id": self.next_group_id}
        data.update({str(k): v for k, v in self.groups.items()})
        self.db.save_groups(data)
