"""QA-owned bounded socket peer. No pipe or captured output is needed for its readiness."""

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import psutil

root = Path(sys.argv[1])
if sys.argv[2] == "child":
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server.settimeout(10)
        pending = root / "child.pending"
        pending.write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "created": psutil.Process().create_time(),
                    "port": server.getsockname()[1],
                }
            )
        )
        pending.replace(root / "child.ready")
        connection, _ = server.accept()
        with connection:
            connection.settimeout(10)
            connection.recv(1)
else:
    child = subprocess.Popen(
        [sys.executable, __file__, str(root), "child"], stdout=None, stderr=None
    )
    deadline = time.monotonic() + 10
    while not (root / "root.release").exists() and time.monotonic() < deadline:
        threading.Event().wait(0.01)
    sys.exit(7)
