"""Run the gateway: ``python -m dwaar_edge`` (config from DWAAR_EDGE_* environment variables).

Binds the local API to ``DWAAR_EDGE_BIND`` (default 127.0.0.1): there are no inbound internet ports (EDGE-09);
set it to the security-LAN address at commissioning. Starts the background sync worker only if
``DWAAR_EDGE_CLOUD_URL`` is set. Issues no hardware command at any point.
"""

from __future__ import annotations

import os

import uvicorn

from .api import create_app
from .config import EdgeConfig
from .gateway import Gateway
from .sync import HttpxTransport, SyncClient, SyncWorker


def main() -> None:
    config = EdgeConfig.from_env()
    gateway = Gateway(config).start()
    worker: SyncWorker | None = None
    cloud = os.environ.get("DWAAR_EDGE_CLOUD_URL")
    if cloud:
        worker = SyncWorker(SyncClient(gateway, HttpxTransport(cloud)))
        worker.start()
    try:
        uvicorn.run(
            create_app(gateway),
            host=os.environ.get("DWAAR_EDGE_BIND", "127.0.0.1"),
            port=int(os.environ.get("DWAAR_EDGE_PORT", "8780")),
            access_log=False,
        )
    finally:
        if worker is not None:
            worker.stop()
        gateway.stop()


if __name__ == "__main__":
    main()
