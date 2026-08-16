#!/usr/bin/env python3
"""Minimal authoritative DNS stub for the two explicitly pinned relay names."""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import signal
import socket
import socketserver
import struct
import threading
from pathlib import Path


ALLOWED_NAMES = {"mask.icloud.com", "mask-h2.icloud.com"}
EXPECTED_QUERY_TYPES = {1, 28, 65}  # A, AAAA, and HTTPS.
RESOLVER_DISCOVERY_NAME = "_dns.resolver.arpa"


def parse_question(packet: bytes) -> tuple[str, int, int, bytes]:
    if len(packet) < 12:
        raise ValueError("short DNS packet")
    labels = []
    offset = 12
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed question names are not supported")
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length
    if offset + 4 > len(packet):
        raise ValueError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return ".".join(labels).lower(), qtype, qclass, packet[12 : offset + 4]


def encode_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    return b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"


def negative_authority(ttl: int) -> bytes:
    # A minimal SOA makes authoritative NODATA/NXDOMAIN replies complete and
    # cacheable.  The owner name points to the question at offset 12.
    rdata = (
        encode_name("localhost.")
        + encode_name("hostmaster.localhost.")
        + struct.pack("!IIIII", 1, 60, 60, 300, ttl)
    )
    return b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, ttl, len(rdata)) + rdata


def response_for(packet: bytes, ipv4: str, ttl: int) -> bytes:
    transaction, request_flags, questions, _, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if questions != 1:
        raise ValueError("exactly one DNS question is required")
    name, qtype, qclass, question = parse_question(packet)
    allowed = name in ALLOWED_NAMES and qclass == 1
    answer = b""
    answer_count = 0
    authority = b""
    authority_count = 0
    rcode = 0 if allowed else 3
    if allowed and qtype == 1:
        answer = (
            b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, ttl, 4)
            + socket.inet_aton(ipv4)
        )
        answer_count = 1
    else:
        # AAAA and HTTPS receive authoritative NODATA to prevent IPv6 bypass
        # and make the client fall back to the pinned A record. Unexpected
        # names receive a complete authoritative NXDOMAIN response.
        authority = negative_authority(ttl)
        authority_count = 1
    flags = 0x8400 | (request_flags & 0x0100) | rcode
    header = struct.pack(
        "!HHHHHH", transaction, flags, 1, answer_count, authority_count, 0
    )
    return header + question + answer + authority


class DnsMixin:
    ipv4: str
    ttl: int
    query_log: Path
    query_log_lock: threading.Lock

    def answer(self, packet: bytes, transport: str, client: str) -> bytes | None:
        try:
            name, qtype, _qclass, _question = parse_question(packet)
            record = {
                "recorded_utc": dt.datetime.now(dt.timezone.utc)
                .isoformat(timespec="microseconds")
                .replace("+00:00", "Z"),
                "name": name,
                "qtype": qtype,
                "transport": transport,
                "client": client,
                "supported": (
                    name in ALLOWED_NAMES and qtype in EXPECTED_QUERY_TYPES
                )
                or (name == RESOLVER_DISCOVERY_NAME and qtype == 64),
            }
            with self.query_log_lock:
                with self.query_log.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
            return response_for(packet, self.ipv4, self.ttl)
        except (ValueError, UnicodeDecodeError, struct.error):
            return None


class UdpServer(DnsMixin, socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, sock = self.request
        response = self.server.answer(packet, "udp", self.client_address[0])
        if response:
            sock.sendto(response, self.client_address)


class TcpServer(DnsMixin, socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        length_data = self.request.recv(2)
        if len(length_data) != 2:
            return
        length = struct.unpack("!H", length_data)[0]
        packet = b""
        while len(packet) < length:
            chunk = self.request.recv(length - len(packet))
            if not chunk:
                return
            packet += chunk
        response = self.server.answer(packet, "tcp", self.client_address[0])
        if response:
            self.request.sendall(struct.pack("!H", len(response)) + response)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--ttl", type=int, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--query-log", type=Path, required=True)
    args = parser.parse_args()
    args.ipv4 = str(ipaddress.IPv4Address(args.ipv4))
    if not 1 <= args.port <= 65535 or not 1 <= args.ttl <= 3600:
        parser.error("port or TTL is outside the permitted range")

    udp = UdpServer((args.address, args.port), UdpHandler)
    tcp = TcpServer((args.address, args.port), TcpHandler)
    query_log_lock = threading.Lock()
    for server in (udp, tcp):
        server.ipv4 = args.ipv4
        server.ttl = args.ttl
        server.query_log = args.query_log
        server.query_log_lock = query_log_lock

    stop = threading.Event()

    def terminate(_signum: int, _frame: object) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    threads = [
        threading.Thread(target=udp.serve_forever, daemon=True),
        threading.Thread(target=tcp.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    args.ready_file.write_text(f"pid={os.getpid()}\n", encoding="utf-8")
    while not stop.wait(0.5):
        pass
    udp.shutdown()
    tcp.shutdown()
    udp.server_close()
    tcp.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
