import asyncio
import sys
import os

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
    conn     = ServerConnection()
    keystore = Keystore()
    e2e      = E2ELayer(conn, keystore)
    e2e.init(SERVER_CERT_PATH)
    groups   = GroupLayer(conn, e2e, keystore)

    messaging  = MessagingService(conn, keystore, e2e, groups)
    view       = ChatView()
    controller = Controller(view, messaging)

    await controller.run()


if __name__ == "__main__":
    asyncio.run(main())
