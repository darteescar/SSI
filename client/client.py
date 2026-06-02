import asyncio
import sys
import os
import threading

_CLIENT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from net.server_conn import ServerConnection, SERVER_CERT_PATH
from crypto.keystore import Keystore
from crypto.e2e import E2ELayer
from crypto.groups import GroupLayer
from app.messaging import MessagingService
from app.controller import Controller
from ui.view import ChatView


async def main():
    ui_lock  = threading.Lock()
    conn     = ServerConnection()
    keystore = Keystore()
    e2e      = E2ELayer(conn, keystore)
    e2e.init(SERVER_CERT_PATH)
    groups   = GroupLayer(conn, e2e, keystore)

    messaging  = MessagingService(conn, keystore, e2e, groups, ui_lock)
    view       = ChatView()
    controller = Controller(view, messaging, ui_lock)

    await controller.run()


if __name__ == "__main__":
    asyncio.run(main())
