import datetime


class GroupManagerMixin:
    def _store_invite_nolock(self, user_id: int, invite: dict):
        self.invites.setdefault(user_id, []).append(invite)
        self._save_invites()

    def _delete_invite_nolock(self, user_id: int, group_id: int):
        self.invites[user_id] = [
            inv for inv in self.invites.get(user_id, [])
            if inv.get("group_id") != group_id
        ]
        self._save_invites()

    def create_group(self, group_name: str, members: list[str], owner: str) -> bool:
        with self.lock:
            if group_name in self.groupname_to_id:
                return False
            owner_id = self.username_to_id.get(owner)
            if owner_id is None:
                return False
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            member_ids = [
                mid for m in members
                if (mid := self.username_to_id.get(m)) is not None and mid != owner_id
            ]
            group_id = self.next_group_id
            self.next_group_id += 1
            for mid in member_ids:
                self._store_invite_nolock(mid, {
                    "group_id":   group_id,
                    "group_name": group_name,
                    "from_id":    owner_id,
                    "from_name":  owner,
                    "text":       f"Convite para o grupo '{group_name}'",
                    "timestamp":  ts,
                })
            self.groups[group_id] = {
                "name":    group_name,
                "members": [owner_id],
                "owner":   owner_id,
                "invited": member_ids,
            }
            self.groupname_to_id[group_name] = group_id
            self._save_groups()
            return True

    def get_groups(self, username: str) -> dict[str, list[str]]:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return {}
            return {
                info["name"]: [
                    self.users[m]["username"] for m in info["members"] if m in self.users
                ]
                for info in self.groups.values()
                if uid in info["members"]
            }

    def leave_group(self, group_name: str, username: str) -> bool:
        with self.lock:
            gid = self.groupname_to_id.get(group_name)
            uid = self.username_to_id.get(username)
            if gid is None or uid is None:
                return False
            group = self.groups.get(gid)
            if group is None or uid not in group["members"] or uid == group["owner"]:
                return False
            group["members"].remove(uid)
            self._save_groups()
            return True

    def accept_invite(self, group_name: str, username: str) -> bool:
        with self.lock:
            gid = self.groupname_to_id.get(group_name)
            uid = self.username_to_id.get(username)
            if gid is None or uid is None:
                return False
            group = self.groups.get(gid)
            if group is None or uid in group["members"] or uid not in group.get("invited", []):
                return False
            group["invited"].remove(uid)
            group["members"].append(uid)
            self._save_groups()
            self._delete_invite_nolock(uid, gid)
            return True

    def reject_invite(self, group_name: str, username: str) -> bool:
        with self.lock:
            gid = self.groupname_to_id.get(group_name)
            uid = self.username_to_id.get(username)
            if gid is None or uid is None:
                return False
            group = self.groups.get(gid)
            if group is None or uid in group["members"] or uid not in group.get("invited", []):
                return False
            group["invited"].remove(uid)
            self._save_groups()
            self._delete_invite_nolock(uid, gid)
            return True

    def delete_group(self, group_name: str, owner: str) -> bool:
        with self.lock:
            gid      = self.groupname_to_id.get(group_name)
            owner_id = self.username_to_id.get(owner)
            if gid is None or owner_id is None:
                return False
            group = self.groups.get(gid)
            if group is None or group["owner"] != owner_id:
                return False
            del self.groups[gid]
            del self.groupname_to_id[group_name]
            self._save_groups()
            for uid in list(self.invites.keys()):
                self.invites[uid] = [
                    inv for inv in self.invites[uid] if inv.get("group_id") != gid
                ]
            self._save_invites()
            return True

    def get_invites(self, username: str) -> list[dict]:
        with self.lock:
            uid = self.username_to_id.get(username)
            if uid is None:
                return []
            return list(self.invites.get(uid, []))

    def get_group_members(self, group_name: str) -> list[str]:
        with self.lock:
            gid = self.groupname_to_id.get(group_name)
            if gid is None:
                return []
            group = self.groups.get(gid, {})
            return [self.users[m]["username"] for m in group.get("members", []) if m in self.users]

    def get_group_owner(self, group_name: str) -> str | None:
        with self.lock:
            gid = self.groupname_to_id.get(group_name)
            if gid is None:
                return None
            group = self.groups.get(gid)
            if group is None:
                return None
            entry = self.users.get(group["owner"])
            return entry["username"] if entry else None

    def exists_group(self, group_name: str) -> bool:
        with self.lock:
            return group_name in self.groupname_to_id

    def is_group_member(self, group_name: str, username: str) -> bool:
        with self.lock:
            gid = self.groupname_to_id.get(group_name)
            uid = self.username_to_id.get(username)
            if gid is None or uid is None:
                return False
            group = self.groups.get(gid)
            return group is not None and uid in group.get("members", [])

    def add_group_member(self, group_name: str, new_member: str, owner: str) -> tuple[bool, str]:
        with self.lock:
            gid      = self.groupname_to_id.get(group_name)
            owner_id = self.username_to_id.get(owner)
            new_uid  = self.username_to_id.get(new_member)
            if gid is None or owner_id is None:
                return False, "Grupo não encontrado."
            if new_uid is None:
                return False, f"Utilizador '{new_member}' não encontrado."
            group = self.groups.get(gid)
            if group is None or group["owner"] != owner_id:
                return False, "Só o dono do grupo pode adicionar membros."
            if new_uid in group["members"]:
                return False, f"'{new_member}' já é membro do grupo."
            if new_uid in group.get("invited", []):
                return False, f"'{new_member}' já tem um convite pendente."
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self._store_invite_nolock(new_uid, {
                "group_id":   gid,
                "group_name": group_name,
                "from_id":    owner_id,
                "from_name":  owner,
                "text":       f"Convite para o grupo '{group_name}'",
                "timestamp":  ts,
            })
            group.setdefault("invited", []).append(new_uid)
            self._save_groups()
            return True, ""

    def kick_group_member(self, group_name: str, member: str, owner: str) -> tuple[bool, str]:
        with self.lock:
            gid      = self.groupname_to_id.get(group_name)
            owner_id = self.username_to_id.get(owner)
            uid      = self.username_to_id.get(member)
            if gid is None or owner_id is None:
                return False, "Grupo não encontrado."
            if uid is None:
                return False, f"Utilizador '{member}' não encontrado."
            group = self.groups.get(gid)
            if group is None or group["owner"] != owner_id:
                return False, "Só o dono do grupo pode remover membros."
            if uid == owner_id:
                return False, "O dono do grupo não pode ser removido."
            if uid in group["members"]:
                group["members"].remove(uid)
                self._save_groups()
                return True, ""
            if uid in group.get("invited", []):
                group["invited"].remove(uid)
                self._delete_invite_nolock(uid, gid)
                self._save_groups()
                return True, ""
            return False, f"'{member}' não é membro nem tem convite pendente no grupo."
