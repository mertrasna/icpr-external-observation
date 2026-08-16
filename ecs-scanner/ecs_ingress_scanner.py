#!/usr/bin/env python3
"""Minimal, resumable IPv4 ECS scanner for iCloud Private Relay ingress DNS."""

import argparse
import csv
import gzip
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path


CSV_FIELDS = ("query_utc", "ecs_prefix", "returned_scope", "answer_ip")
STATUS_RE = re.compile(r"status:\s*([A-Z]+)")
ECS_RE = re.compile(r"CLIENT-SUBNET:\s*([0-9.]+)/(\d+)/(\d+)")
A_RE = re.compile(r"^\S+\s+\d+\s+IN\s+A\s+(\S+)\s*$")


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iter_prefixes(path):
    """Yield validated, strictly increasing public IPv4 /24 networks."""
    previous = -1
    with path.open() as handle:
        for line_number, raw in enumerate(handle, 1):
            value = raw.split("#", 1)[0].strip()
            if not value:
                continue
            try:
                network = ipaddress.ip_network(value, strict=True)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc
            if network.version != 4 or network.prefixlen != 24:
                raise ValueError(f"{path}:{line_number}: expected an IPv4 /24: {value}")
            if not network.is_global:
                raise ValueError(f"{path}:{line_number}: not public IPv4 space: {value}")
            current = int(network.network_address)
            if current <= previous:
                raise ValueError(
                    f"{path}:{line_number}: prefixes must be sorted and unique: {value}"
                )
            previous = current
            yield network


def validate_and_count_prefixes(path):
    return sum(1 for _ in iter_prefixes(path))


def parse_dig_output(output):
    status_match = STATUS_RE.search(output)
    status = status_match.group(1) if status_match else None

    scope = None
    ecs_match = ECS_RE.search(output)
    if ecs_match:
        source_length = int(ecs_match.group(2))
        candidate_scope = int(ecs_match.group(3))
        if source_length == 24 and 0 <= candidate_scope <= 24:
            scope = candidate_scope

    addresses = []
    for line in output.splitlines():
        match = A_RE.match(line)
        if not match:
            continue
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        if address.version == 4:
            addresses.append(str(address))
    return status, scope, addresses


def query_dns(dig, target, server, prefix, timeout):
    command = [
        dig,
        target,
        "A",
        f"@{server}",
        f"+subnet={prefix}",
        f"+time={timeout}",
        "+tries=1",
        "+noall",
        "+comments",
        "+answer",
        "+additional",
    ]
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    output = completed.stdout + completed.stderr
    status, scope, addresses = parse_dig_output(output)
    if completed.returncode != 0:
        raise RuntimeError(f"dig exited {completed.returncode}")
    if status != "NOERROR":
        raise RuntimeError(f"DNS status {status or 'missing'}")
    return scope, addresses


def read_summary(path):
    values = {}
    if path.exists():
        for line in path.read_text().splitlines():
            key, separator, value = line.partition(":")
            if separator:
                values[key.strip()] = value.strip()
    return values


def integer(values, key, default=0):
    try:
        return int(values.get(key, default))
    except (TypeError, ValueError):
        return default


def read_existing_addresses(path):
    addresses = set()
    if not path.exists():
        return addresses
    with path.open(newline="") as handle:
        for row in csv.DictReader(handle):
            answer = row.get("answer_ip", "")
            try:
                if answer and ipaddress.ip_address(answer).version == 4:
                    addresses.add(answer)
            except ValueError:
                pass
    return addresses


def write_unique(path, addresses):
    ordered = sorted(addresses, key=ipaddress.ip_address)
    path.write_text("".join(f"{address}\n" for address in ordered))


def write_summary(path, state, *, end=None):
    pending = ",".join(sorted(
        state["pending_errors"],
        key=lambda value: int(ipaddress.ip_network(value).network_address),
    ))
    lines = [
        f"scan_start_utc: {state['start']}",
        f"scan_end_utc: {end or ''}",
        f"run_status: {state['status']}",
        f"dns_target: {state['target']}",
        f"dns_server: {state['server']}",
        f"source_input: {state['input']}",
        f"query_rate_limit_per_second: {state['rate']}",
        f"dns_concurrency: {state['concurrency']}",
        f"ecs_24_inputs: {state['total_inputs']}",
        f"inputs_processed: {state['processed']}",
        f"last_processed_prefix: {state['last_prefix']}",
        f"skip_until_ipv4: {state['skip_until']}",
        f"dns_queries_sent: {state['queries']}",
        f"skipped_by_returned_scope: {state['scope_skips']}",
        f"errors_or_timeouts: {state['errors']}",
        f"pending_error_prefixes: {pending}",
        f"unique_ingress_ipv4_addresses: {len(state['addresses'])}",
    ]
    with path.open("w") as handle:
        handle.write("\n".join(lines) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def checkpoint(results_handle, unique_path, summary_path, state, *, final=False):
    results_handle.flush()
    os.fsync(results_handle.fileno())
    write_unique(unique_path, state["addresses"])
    write_summary(summary_path, state, end=utc_now() if final else None)


class RateLimiter:
    def __init__(self, rate):
        self.interval = 1.0 / rate
        self.next_start = time.monotonic()
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            delay = self.next_start - now
            if delay > 0:
                time.sleep(delay)
            self.next_start = time.monotonic() + self.interval


def append_result(writer, handle, query_time, prefix, scope, addresses):
    for address in addresses or [""]:
        writer.writerow({
            "query_utc": query_time,
            "ecs_prefix": str(prefix),
            "returned_scope": "" if scope is None else scope,
            "answer_ip": address,
        })
    handle.flush()


def query_with_retries(prefix, args, dig, limiter):
    last_error = None
    attempts = 0
    errors = 0
    for _ in range(args.retries):
        limiter.wait()
        attempts += 1
        try:
            scope, found = query_dns(
                dig, args.target, args.server, str(prefix), args.timeout
            )
        except RuntimeError as exc:
            errors += 1
            last_error = exc
            continue

        return {
            "prefix": prefix,
            "query_time": utc_now(),
            "scope": scope,
            "addresses": found,
            "attempts": attempts,
            "errors": errors,
            "error": None,
        }
    return {
        "prefix": prefix,
        "query_time": None,
        "scope": None,
        "addresses": [],
        "attempts": attempts,
        "errors": errors,
        "error": last_error,
    }


def record_outcome(outcome, writer, results_handle, state):
    state["queries"] += outcome["attempts"]
    state["errors"] += outcome["errors"]
    if outcome["error"] is not None:
        return
    append_result(
        writer,
        results_handle,
        outcome["query_time"],
        outcome["prefix"],
        outcome["scope"],
        outcome["addresses"],
    )
    state["addresses"].update(outcome["addresses"])


def progress_line(state, started):
    elapsed = max(time.monotonic() - started, 0.001)
    done_this_run = state["processed"] - state["processed_at_start"]
    speed = done_this_run / elapsed
    remaining = max(state["total_inputs"] - state["processed"], 0)
    eta_hours = remaining / speed / 3600 if speed else float("inf")
    eta = f"{eta_hours:.1f}h" if eta_hours != float("inf") else "unknown"
    return (
        f"progress={state['processed']}/{state['total_inputs']} "
        f"queries={state['queries']} scope_skips={state['scope_skips']} "
        f"errors={state['errors']} unique={len(state['addresses'])} eta={eta}"
    )


def open_text_auto(path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt")
    return path.open()


def build_sources(snapshot, output):
    """Expand a CAIDA RouteViews pfx2as snapshot to sorted public /24s."""
    marked = bytearray(1 << 24)
    with open_text_auto(snapshot) as handle:
        for line_number, raw in enumerate(handle, 1):
            fields = raw.split()
            if len(fields) < 2:
                continue
            try:
                network = ipaddress.ip_network(f"{fields[0]}/{fields[1]}", strict=False)
            except ValueError as exc:
                raise ValueError(f"{snapshot}:{line_number}: {exc}") from exc
            if network.version != 4:
                continue
            # A full RouteViews table should not contain a default or another
            # prefix broader than an allocated /8. Ignore one if present.
            if network.prefixlen < 8:
                continue
            first = int(network.network_address) >> 8
            last = int(network.broadcast_address) >> 8
            marked[first:last + 1] = b"\x01" * (last - first + 1)

    count = 0
    chunk = []
    with output.open("w") as handle:
        for index, present in enumerate(marked):
            if not present:
                continue
            network = ipaddress.ip_network((index << 8, 24))
            if not network.is_global:
                continue
            chunk.append(f"{network}\n")
            count += 1
            if len(chunk) == 10_000:
                handle.writelines(chunk)
                chunk.clear()
        handle.writelines(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    print(f"Wrote {count} sorted public announced /24s to {output}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("."))
    parser.add_argument("--target", default="mask.apple-dns.net")
    parser.add_argument(
        "--server",
        help="authoritative DNS server selected and recorded for this run",
    )
    parser.add_argument("--dig", default="dig", help=argparse.SUPPRESS)
    timing = parser.add_mutually_exclusive_group()
    timing.add_argument("--rate", type=float, default=None,
                        help="maximum query starts per second (default: 1)")
    timing.add_argument("--delay", type=float, default=None,
                        help="legacy equivalent: minimum seconds between query starts")
    parser.add_argument("--timeout", type=int, default=3)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="maximum in-flight DNS queries sharing the aggregate rate limit (default: 1)",
    )
    parser.add_argument("--checkpoint-seconds", type=float, default=30)
    parser.add_argument("--max-consecutive-failures", type=int, default=5)
    parser.add_argument("--build-sources", type=Path, metavar="PFX2AS[.GZ]")
    parser.add_argument("--write-input", type=Path, default=Path("ecs_sources.txt"))
    args = parser.parse_args()

    if args.build_sources:
        try:
            build_sources(args.build_sources, args.write_input)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        return 0

    if not args.server:
        parser.error(
            "--server is required for live collection; discover and record a "
            "currently authoritative server before the run"
        )
    if args.input is None:
        args.input = Path("ecs_sources.txt")
    if args.delay is not None:
        if args.delay <= 0:
            parser.error("--delay must be positive")
        rate = 1.0 / args.delay
    else:
        rate = args.rate if args.rate is not None else 1.0
    if rate <= 0 or args.timeout < 1 or args.retries < 1 or args.concurrency < 1:
        parser.error("rate, timeout, retries and concurrency must be positive")
    if args.checkpoint_seconds <= 0 or args.max_consecutive_failures < 1:
        parser.error("checkpoint interval and failure limit must be positive")

    dig = shutil.which(args.dig)
    if not dig:
        parser.error(f"{args.dig} was not found")
    try:
        total_inputs = validate_and_count_prefixes(args.input)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    if total_inputs == 0:
        parser.error(f"{args.input} contains no prefixes")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    results_path = args.output_dir / "results.csv"
    unique_path = args.output_dir / "unique_ingress_ips.txt"
    summary_path = args.output_dir / "summary.txt"
    previous = read_summary(summary_path)

    if (
        results_path.exists()
        and results_path.stat().st_size
        and "inputs_processed" not in previous
    ):
        parser.error(
            f"{args.output_dir} contains pre-streaming results; use a new output directory"
        )
    for key, expected in (("dns_target", args.target), ("dns_server", args.server)):
        if previous.get(key) and previous[key] != expected:
            parser.error(f"existing {key} is {previous[key]!r}, not {expected!r}")
    resolved_input = str(args.input.resolve())
    if previous.get("source_input") and previous["source_input"] != resolved_input:
        parser.error("existing output directory belongs to a different source input")
    if previous.get("ecs_24_inputs") and integer(previous, "ecs_24_inputs") != total_inputs:
        parser.error("source input count changed since this scan started")

    addresses = read_existing_addresses(results_path)
    pending = {item for item in previous.get("pending_error_prefixes", "").split(",") if item}
    last_prefix = previous.get("last_processed_prefix", "")
    skip_until = previous.get("skip_until_ipv4", "")
    state = {
        "start": previous.get("scan_start_utc") or utc_now(),
        "status": "running",
        "target": args.target,
        "server": args.server,
        "input": resolved_input,
        "rate": f"{rate:g}",
        "concurrency": args.concurrency,
        "total_inputs": total_inputs,
        "processed": integer(previous, "inputs_processed"),
        "last_prefix": last_prefix,
        "skip_until": skip_until,
        "queries": integer(previous, "dns_queries_sent"),
        "scope_skips": integer(previous, "skipped_by_returned_scope"),
        "errors": integer(previous, "errors_or_timeouts"),
        "pending_errors": pending,
        "addresses": addresses,
    }
    state["processed_at_start"] = state["processed"]
    last_prefix_int = int(ipaddress.ip_network(last_prefix).network_address) if last_prefix else -1
    skip_until_int = int(ipaddress.ip_address(skip_until)) if skip_until else -1

    new_file = not results_path.exists() or results_path.stat().st_size == 0
    limiter = RateLimiter(rate)
    started = time.monotonic()
    last_checkpoint = started
    next_progress = state["processed"] + 1_000
    consecutive_failures = 0
    interrupted = False

    with results_path.open("a", newline="", buffering=1) as results_handle:
        writer = csv.DictWriter(results_handle, fieldnames=CSV_FIELDS)
        if new_file:
            writer.writeheader()
            results_handle.flush()
        checkpoint(results_handle, unique_path, summary_path, state)
        try:
            # Retry unresolved prefixes from a prior run before advancing.
            for value in list(sorted(
                state["pending_errors"],
                key=lambda item: int(ipaddress.ip_network(item).network_address),
            )):
                prefix = ipaddress.ip_network(value)
                outcome = query_with_retries(prefix, args, dig, limiter)
                record_outcome(outcome, writer, results_handle, state)
                if outcome["error"]:
                    consecutive_failures += 1
                    print(
                        f"ERROR {prefix}: {outcome['error']}",
                        file=sys.stderr,
                        flush=True,
                    )
                    if consecutive_failures >= args.max_consecutive_failures:
                        state["status"] = "stopped_after_consecutive_failures"
                        break
                else:
                    state["pending_errors"].discard(value)
                    consecutive_failures = 0

            if state["status"] == "running":
                prefix_iterator = iter(iter_prefixes(args.input))
                queue = deque()
                input_exhausted = False

                def fill_queue(executor):
                    nonlocal input_exhausted
                    while len(queue) < args.concurrency and not input_exhausted:
                        try:
                            prefix = next(prefix_iterator)
                        except StopIteration:
                            input_exhausted = True
                            break
                        prefix_int = int(prefix.network_address)
                        if prefix_int <= last_prefix_int:
                            continue
                        if prefix_int <= skip_until_int:
                            queue.append((prefix, None))
                        else:
                            future = executor.submit(
                                query_with_retries,
                                prefix,
                                args,
                                dig,
                                limiter,
                            )
                            queue.append((prefix, future))

                with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
                    fill_queue(executor)
                    while queue:
                        prefix, future = queue[0]
                        prefix_int = int(prefix.network_address)

                        if prefix_int <= skip_until_int:
                            if future is not None:
                                redundant = future.result()
                                state["queries"] += redundant["attempts"]
                                state["errors"] += redundant["errors"]
                            state["scope_skips"] += 1
                        else:
                            outcome = future.result()
                            record_outcome(outcome, writer, results_handle, state)
                            if outcome["error"]:
                                state["pending_errors"].add(str(prefix))
                                consecutive_failures += 1
                                print(
                                    f"ERROR {prefix}: {outcome['error']}",
                                    file=sys.stderr,
                                    flush=True,
                                )
                            else:
                                state["pending_errors"].discard(str(prefix))
                                consecutive_failures = 0
                                if (
                                    outcome["scope"] is not None
                                    and outcome["scope"] < 24
                                ):
                                    covered = ipaddress.ip_network(
                                        (
                                            prefix.network_address,
                                            outcome["scope"],
                                        ),
                                        strict=False,
                                    )
                                    skip_until_int = max(
                                        skip_until_int,
                                        int(covered.broadcast_address),
                                    )
                                    state["skip_until"] = str(
                                        ipaddress.ip_address(skip_until_int)
                                    )

                        queue.popleft()
                        state["processed"] += 1
                        state["last_prefix"] = str(prefix)
                        last_prefix_int = prefix_int

                        now = time.monotonic()
                        if state["processed"] >= next_progress:
                            print(progress_line(state, started), flush=True)
                            next_progress = state["processed"] + 1_000
                        if now - last_checkpoint >= args.checkpoint_seconds:
                            checkpoint(
                                results_handle,
                                unique_path,
                                summary_path,
                                state,
                            )
                            last_checkpoint = now
                        if (
                            consecutive_failures
                            >= args.max_consecutive_failures
                        ):
                            state["status"] = "stopped_after_consecutive_failures"
                            break
                        fill_queue(executor)

                if state["status"] == "running":
                    state["status"] = (
                        "completed_with_pending_errors"
                        if state["pending_errors"] else "completed"
                    )
        except KeyboardInterrupt:
            interrupted = True
            state["status"] = "stopped_early"
            print("\nStopped; completed results and checkpoint are saved.", file=sys.stderr)

        checkpoint(results_handle, unique_path, summary_path, state, final=True)

    print(progress_line(state, started))
    print(f"Unique ingress IPv4 addresses: {len(addresses)}")
    return 130 if interrupted else (1 if state["status"].startswith("stopped") else 0)


if __name__ == "__main__":
    raise SystemExit(main())
