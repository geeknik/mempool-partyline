"""Bitcoin mempool monitoring via ZMQ and polling.

Two monitors are provided:

* :class:`MempoolMonitor` -- subscribes to Bitcoin Core's ``rawtx`` ZMQ topic
  for real-time transaction notifications (preferred).
* :class:`PollingMonitor` -- falls back to periodic RPC polling when ZMQ is
  not available.

Both expose the same shape: ``start()``, ``stop()``, ``poll_once()`` and
``run_loop()``, so the rest of the application can treat them uniformly.
"""

import logging
import time
from collections.abc import Callable

import zmq

from partyline.constants import (
    DEFAULT_TESTNET_PORT,
    DEFAULT_ZMQ_PORT,
    POLL_INTERVAL_SECONDS,
)

logger = logging.getLogger(__name__)

__all__ = [
    "MempoolMonitor",
    "PollingMonitor",
    "create_monitor",
]

DEFAULT_RPC_URL = f"http://127.0.0.1:{DEFAULT_TESTNET_PORT}"
DEFAULT_ZMQ_ENDPOINT = f"tcp://127.0.0.1:{DEFAULT_ZMQ_PORT}"
DEFAULT_POLL_INTERVAL = float(POLL_INTERVAL_SECONDS)


class MempoolMonitor:
    """ZMQ-based real-time mempool monitor."""

    def __init__(
        self,
        zmq_endpoint: str = DEFAULT_ZMQ_ENDPOINT,
        on_tx: Callable[[bytes], None] | None = None,
    ) -> None:
        self.zmq_endpoint = zmq_endpoint
        self.on_tx = on_tx
        self._running = False
        self._context: zmq.Context | None = None
        self._socket: zmq.Socket | None = None

    def start(self) -> None:
        """Open the ZMQ subscription."""
        self._running = True
        self._context = zmq.Context()
        self._socket = self._context.socket(zmq.SUB)
        self._socket.connect(self.zmq_endpoint)
        self._socket.setsockopt(zmq.SUBSCRIBE, b"rawtx")
        logger.info("ZMQ monitor started on %s", self.zmq_endpoint)

    def stop(self) -> None:
        """Close the ZMQ subscription."""
        self._running = False
        sock, ctx = self._socket, self._context
        self._socket = None
        self._context = None
        if sock is not None:
            sock.close(linger=0)
        if ctx is not None:
            ctx.term()
        logger.info("ZMQ monitor stopped")

    def poll_once(self) -> bytes | None:
        """Return the next raw transaction payload, or ``None`` if idle."""
        sock = self._socket
        if sock is None:
            return None
        try:
            return sock.recv(flags=zmq.NOBLOCK)
        except zmq.Again:
            return None

    def run_loop(self) -> None:
        """Run the blocking receive loop until :meth:`stop` is called."""
        self.start()
        try:
            while self._running:
                data = self.poll_once()
                if data is not None and self.on_tx is not None:
                    self.on_tx(data)
        finally:
            self.stop()


class PollingMonitor:
    """Fallback polling-based mempool monitor."""

    def __init__(
        self,
        rpc_url: str = DEFAULT_RPC_URL,
        on_tx: Callable[[bytes], None] | None = None,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> None:
        self.rpc_url = rpc_url
        self.on_tx = on_tx
        self.poll_interval = poll_interval
        self._running = False
        self._seen_hashes: set[str] = set()

    def start(self) -> None:
        """Begin polling."""
        self._running = True
        logger.info(
            "Polling monitor started (interval=%ss, rpc=%s)",
            self.poll_interval,
            self.rpc_url,
        )

    def stop(self) -> None:
        """Stop polling."""
        self._running = False
        logger.info("Polling monitor stopped")

    def poll_once(self) -> list[bytes]:
        """Return newly observed transactions since the last poll."""
        if not self._running:
            return []
        # NOTE: The RPC-backed implementation is layered on top of this class
        # in partyline.transport.rpc; this base variant yields nothing so it can
        # be used as a no-op monitor in tests and offline mode.
        return []

    def run_loop(self) -> None:
        """Run the blocking poll loop until :meth:`stop` is called."""
        self.start()
        try:
            while self._running:
                for tx in self.poll_once():
                    if self.on_tx is not None:
                        self.on_tx(tx)
                time.sleep(self.poll_interval)
        finally:
            self.stop()


def create_monitor(
    rpc_url: str = DEFAULT_RPC_URL,
    zmq_endpoint: str = DEFAULT_ZMQ_ENDPOINT,
    on_tx: Callable[[bytes], None] | None = None,
    use_zmq: bool = True,
) -> MempoolMonitor | PollingMonitor:
    """Build the best available monitor, preferring ZMQ over polling."""
    if use_zmq:
        return MempoolMonitor(zmq_endpoint=zmq_endpoint, on_tx=on_tx)
    return PollingMonitor(rpc_url=rpc_url, on_tx=on_tx)
