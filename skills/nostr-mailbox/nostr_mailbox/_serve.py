"""An accept loop for the small in-process servers (the signer socket, the loopback
relay and blob server): one daemon thread per connection, and a `stop()` that returns
as soon as the loop has exited. The loop blocks in `accept()`; `stop()` wakes it with
one connection to itself, so nothing here polls on an interval."""
from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Callable


class Listener:
    def __init__(self, sock: socket.socket, handle: Callable[[socket.socket], None],
                 name: str):
        self._sock, self._handle, self._name = sock, handle, name
        self._stopping = threading.Event()
        self._thread = threading.Thread(target=self._loop, name=name, daemon=True)

    def start(self) -> Listener:
        self._thread.start()
        return self

    def _loop(self) -> None:
        while True:
            try:
                connection, _ = self._sock.accept()
            except OSError:                 # the listening socket is gone
                return
            if self._stopping.is_set():
                connection.close()
                return
            threading.Thread(target=self._handle, args=(connection,),
                             name=f"{self._name}-conn", daemon=True).start()

    def stop(self) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        with contextlib.suppress(OSError), socket.socket(self._sock.family,
                                                         self._sock.type) as waker:
            waker.connect(self._sock.getsockname())
        self._thread.join()
        self._sock.close()
