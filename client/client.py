import asyncio
import sys
import os

_CLIENT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_CLIENT_DIR)
sys.path.insert(0, _CLIENT_DIR)
sys.path.insert(0, _PROJECT_DIR)

from net.network import NetworkClient
from ui.view import ChatView
from app.messaging import MessagingService
from app.controller import Controller


async def main():
    network    = NetworkClient()
    view       = ChatView()
    messaging  = MessagingService(network)
    controller = Controller(view, messaging)
    await controller.run()

if __name__ == "__main__":
    asyncio.run(main())
