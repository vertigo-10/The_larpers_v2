"""SENTRY collector — turns real packets into scored flows.

Runs on a machine you want watched, aggregates captured packets into flows,
and posts them to /api/ingest. This is what makes the dashboard show real
traffic instead of the simulator.

    export SENTRY_API_KEY=sentry_ak_...
    sudo -E python -m agent.sentry_collector --server http://localhost:8000

Two things it deliberately does not do:

* It never reads packet payloads. Only header fields — addresses, ports,
  sizes, timings — are examined, and only counters derived from them are
  ever sent. A tool that watches a network should not become a way to read
  everyone's traffic, and the narrow scope means a compromised collector
  leaks metadata rather than content.
* It never takes the API key on the command line. Arguments are visible in
  `ps` to every user on the box, so the key comes from the environment or a
  file with checked permissions.
"""

import argparse
import os
import signal
import socket
import stat
import sys
import threading
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

try:
    import requests
except ImportError:  # pragma: no cover - dependency guidance
    sys.exit("Missing dependency: pip install -r agent/requirements.txt")

try:
    from scapy.all import IP, IPv6, TCP, UDP, conf, get_if_addr, sniff
except ImportError:  # pragma: no cover - dependency guidance
    sys.exit("Missing dependency: pip install -r agent/requirements.txt")


# Standard NetFlow-style expiry. Idle closes a conversation that has gone
# quiet; active caps a long-lived one so a download that runs for an hour still
# reports progress instead of surfacing as a single flow when it finally ends.
IDLE_TIMEOUT_S = 15.0
ACTIVE_TIMEOUT_S = 60.0

# The server caps a batch at 500.
MAX_BATCH = 500

# Bounded so a server outage costs bounded memory. When it fills, the oldest
# flows are dropped and the loss is logged — silently discarding detection data
# is worse than saying so.
MAX_PENDING = 20_000


class FlowKey(tuple):
    """(peer_ip, local_port, protocol) — the identity of one conversation."""


class FlowTable:
    """Accumulates packets into flows and hands over the ones that have expired.

    Locked because scapy's sniff callback runs on its own thread while the send
    loop drains from the main one.
    """

    def __init__(self, local_addrs: set):
        self._flows: Dict[FlowKey, dict] = {}
        self._lock = threading.Lock()
        self._local = local_addrs
        self.seen_packets = 0
        self.ignored_packets = 0

    def observe(self, packet) -> None:
        parsed = self._parse(packet)
        if parsed is None:
            self.ignored_packets += 1
            return
        key, size, now = parsed
        self.seen_packets += 1

        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                self._flows[key] = {
                    "first": now, "last": now, "packets": 1, "bytes": size,
                }
            else:
                flow["last"] = now
                flow["packets"] += 1
                flow["bytes"] += size

    def _parse(self, packet) -> Optional[Tuple[FlowKey, int, float]]:
        """Reduce a packet to (key, size, timestamp), or None to ignore it.

        Orients the flow so the reported address is always the remote party.
        Incidents are grouped by source address, so pointing that at the local
        machine would collapse every attacker into one meaningless bucket.
        """
        if IP in packet:
            src, dst = packet[IP].src, packet[IP].dst
        elif IPv6 in packet:
            src, dst = packet[IPv6].src, packet[IPv6].dst
        else:
            return None  # ARP, and anything else without an IP layer

        if TCP in packet:
            proto, sport, dport = "TCP", packet[TCP].sport, packet[TCP].dport
        elif UDP in packet:
            proto, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport
        else:
            proto, sport, dport = "OTHER", 0, 0

        src_local = src in self._local
        dst_local = dst in self._local
        if src_local and dst_local:
            return None  # loopback chatter, not network traffic
        if dst_local:
            peer, local_port = src, dport      # inbound: they hit our port
        elif src_local:
            peer, local_port = dst, dport      # outbound: we hit their port
        else:
            # Neither endpoint is ours — only happens on a mirrored/monitor
            # port. Keep it, oriented by convention.
            peer, local_port = src, dport

        return FlowKey((peer, local_port, proto)), len(packet), time.time()

    def expire(self, force: bool = False) -> List[dict]:
        """Remove and return flows past idle or active timeout.

        `force` drains everything, used on shutdown so the last few seconds of
        traffic are not lost.
        """
        now = time.time()
        ready: List[dict] = []

        with self._lock:
            for key in list(self._flows):
                flow = self._flows[key]
                idle = now - flow["last"]
                age = now - flow["first"]
                if not force and idle < IDLE_TIMEOUT_S and age < ACTIVE_TIMEOUT_S:
                    continue

                peer, local_port, proto = key
                duration = max(flow["last"] - flow["first"], 0.0)
                ready.append({
                    "src_ip": peer,
                    "dst_port": int(local_port),
                    "protocol": proto,
                    "duration": round(duration, 6),
                    "packets": int(flow["packets"]),
                    "total_bytes": float(flow["bytes"]),
                })
                del self._flows[key]

        return ready

    def open_count(self) -> int:
        with self._lock:
            return len(self._flows)


class Sender:
    """Posts batches to /api/ingest, with backoff and a bounded buffer."""

    def __init__(self, server: str, api_key: str, node: str, verify_tls: bool = True):
        self.url = server.rstrip("/") + "/api/ingest"
        self.node = node
        self.verify_tls = verify_tls
        self._pending: List[dict] = []
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "sentry-collector/1.0",
        })
        self.sent = 0
        self.dropped = 0
        self._backoff = 1.0

    def queue(self, flows: List[dict]) -> None:
        for f in flows:
            f["node"] = self.node
        self._pending.extend(flows)

        if len(self._pending) > MAX_PENDING:
            lost = len(self._pending) - MAX_PENDING
            # Drop oldest: during an attack the newest flows are the ones an
            # analyst needs, and stale ones have likely already been superseded.
            self._pending = self._pending[lost:]
            self.dropped += lost
            log(f"buffer full — dropped {lost} of the oldest flows")

    def flush(self) -> None:
        while self._pending:
            batch = self._pending[:MAX_BATCH]
            try:
                r = self._session.post(
                    self.url, json={"flows": batch},
                    timeout=10, verify=self.verify_tls,
                )
            except requests.RequestException as exc:
                log(f"send failed ({exc.__class__.__name__}) — retrying in {self._backoff:.0f}s")
                time.sleep(self._backoff)
                self._backoff = min(self._backoff * 2, 60.0)
                return

            if r.status_code == 401:
                # Not retryable, and retrying a bad key forever just fills the
                # server's logs. Stop with a message that names the cause.
                sys.exit("Rejected: API key invalid or revoked. Issue a new one "
                         "in Settings → Collector keys.")
            if r.status_code == 503:
                log("server has no model loaded — holding flows and retrying")
                time.sleep(self._backoff)
                self._backoff = min(self._backoff * 2, 60.0)
                return
            if not r.ok:
                log(f"server returned {r.status_code}: {r.text[:200]}")
                time.sleep(self._backoff)
                self._backoff = min(self._backoff * 2, 60.0)
                return

            self._pending = self._pending[len(batch):]
            self.sent += len(batch)
            self._backoff = 1.0

    def pending_count(self) -> int:
        return len(self._pending)


def log(message: str) -> None:
    print(f"[collector] {message}", flush=True)


def read_api_key(key_file: Optional[str]) -> str:
    """Get the key from a file or the environment, never from argv.

    Command-line arguments are world-readable via `ps`, so a key passed that way
    leaks to every account on the machine.
    """
    if key_file:
        if not os.path.exists(key_file):
            sys.exit(f"Key file not found: {key_file}")
        mode = os.stat(key_file).st_mode
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            sys.exit(f"{key_file} is readable by other users. "
                     f"Fix with: chmod 600 {key_file}")
        with open(key_file) as fh:
            key = fh.read().strip()
    else:
        key = os.environ.get("SENTRY_API_KEY", "").strip()

    if not key:
        sys.exit(
            "No API key. Set SENTRY_API_KEY or pass --key-file.\n"
            "Create one in the dashboard under Settings → Collector keys.\n"
            "Note: with sudo you need -E to keep the variable, e.g.\n"
            "  sudo -E python -m agent.sentry_collector --server http://localhost:8000"
        )
    if not key.startswith("sentry_ak_"):
        sys.exit("That does not look like a SENTRY collector key "
                 "(they start with sentry_ak_).")
    return key


def local_addresses(interface: str) -> set:
    """Addresses belonging to this host, used to orient flow direction."""
    addrs = {"127.0.0.1", "::1"}
    try:
        addrs.add(get_if_addr(interface))
    except Exception:  # noqa: BLE001 - interface may have no IPv4
        pass
    try:
        hostname = socket.gethostname()
        addrs.update(info[4][0] for info in socket.getaddrinfo(hostname, None))
    except socket.gaierror:
        pass
    return {a for a in addrs if a and a != "0.0.0.0"}


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentry-collector",
        description="Capture live traffic and post scored flows to SENTRY.",
    )
    parser.add_argument("--server", default="http://localhost:8000",
                        help="SENTRY base URL (default: %(default)s)")
    parser.add_argument("--interface", "-i", default=None,
                        help="Interface to capture on (default: scapy's default route)")
    parser.add_argument("--node", default=None,
                        help="Name for this sensor in the dashboard (default: hostname)")
    parser.add_argument("--key-file", default=None,
                        help="File containing the API key, mode 600")
    parser.add_argument("--filter", default="ip or ip6",
                        help="BPF capture filter (default: %(default)s)")
    parser.add_argument("--flush-interval", type=float, default=5.0,
                        help="Seconds between sends (default: %(default)s)")
    parser.add_argument("--insecure", action="store_true",
                        help="Skip TLS verification. Only for a self-signed lab server.")
    args = parser.parse_args()

    api_key = read_api_key(args.key_file)
    interface = args.interface or conf.iface
    node = args.node or socket.gethostname().split(".")[0]

    if args.server.startswith("http://") and "localhost" not in args.server \
            and "127.0.0.1" not in args.server:
        log("WARNING: posting over plain HTTP to a remote host. The API key "
            "travels in a header and is readable in transit — use https://.")

    table = FlowTable(local_addresses(str(interface)))
    sender = Sender(args.server, api_key, node, verify_tls=not args.insecure)

    log(f"interface={interface} node={node} server={args.server}")
    log(f"local addresses: {', '.join(sorted(table._local)) or 'none detected'}")
    log("capturing headers only — payloads are never read or transmitted")

    stopping = threading.Event()

    def shutdown(signum, frame):
        if stopping.is_set():
            return
        stopping.set()
        log("stopping — flushing remaining flows")

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    def capture():
        try:
            sniff(iface=interface, filter=args.filter, store=False,
                  prn=table.observe, stop_filter=lambda _p: stopping.is_set())
        except PermissionError:
            log("permission denied — packet capture needs root. Try: sudo -E …")
            stopping.set()
        except Exception as exc:  # noqa: BLE001
            log(f"capture stopped: {exc}")
            stopping.set()

    thread = threading.Thread(target=capture, daemon=True, name="capture")
    thread.start()

    last_report = time.time()
    try:
        while not stopping.is_set():
            time.sleep(args.flush_interval)
            sender.queue(table.expire())
            sender.flush()

            if time.time() - last_report >= 30:
                log(f"sent={sender.sent} open={table.open_count()} "
                    f"queued={sender.pending_count()} packets={table.seen_packets}"
                    + (f" dropped={sender.dropped}" if sender.dropped else ""))
                last_report = time.time()
    finally:
        stopping.set()
        sender.queue(table.expire(force=True))
        sender.flush()
        log(f"done — {sender.sent} flows sent"
            + (f", {sender.dropped} dropped" if sender.dropped else ""))


if __name__ == "__main__":
    main()
