#!/usr/bin/env python3
from __future__ import annotations

import html
import http.client
import logging
import re
import ssl
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from threading import Lock
from itertools import chain
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

USER_AGENT = "Mozilla/5.0 (compatible; SiteTitleChecker/1.0)"
READ_LIMIT = 65536
REQUEST_TIMEOUT = 15
REQUEST_ATTEMPTS = 2


LOGGER = logging.getLogger("site_title_checker")


@dataclass(frozen=True)
class Target:
    ip: str
    port: int

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


def prompt_file_path() -> Path:
    while True:
        path_input = input("Enter the path to the .txt file: ").strip()
        if not path_input:
            print("The path cannot be empty. Try again.")
            continue
        path = Path(path_input)
        if path.is_file():
            return path
        print(f"File '{path}' not found. Check the path and try again.")


def load_targets_from_file(path: Path) -> Dict[str, Set[int]]:
    targets: Dict[str, Set[int]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            ip: Optional[str] = None
            port: Optional[int] = None

            if line.startswith("[") and "]" in line:
                host_part, remainder = line[1:].split("]", 1)
                ip = host_part.strip()
                remainder = remainder.strip()
                if remainder.startswith(":"):
                    port_str = remainder[1:]
                    port = _parse_port(port_str, line_number)
            elif ":" in line:
                ip_part, port_str = line.rsplit(":", 1)
                ip = ip_part.strip()
                port = _parse_port(port_str, line_number)
            else:
                ip = line

            if not ip:
                print(f"Line {line_number}: unable to determine IP address. Skipping.")
                continue

            if port is not None and port == 0:
                continue

            ip_targets = targets.setdefault(ip, set())
            if port is not None:
                ip_targets.add(port)

    return targets


def _parse_port(port_str: str, line_number: int) -> Optional[int]:
    port_str = port_str.strip()
    if not port_str:
        return None
    if not port_str.isdigit():
        print(f"Line {line_number}: port '{port_str}' is not an integer. Skipping.")
        return None
    port = int(port_str)
    if not (1 <= port <= 65535):
        print(f"Line {line_number}: port '{port}' is outside the range 1-65535. Skipping.")
        return None
    return port


def prompt_thread_count() -> int:
    while True:
        value = input("Enter the number of threads: ").strip()
        if not value:
            print("Thread count cannot be empty. Try again.")
            continue
        if not value.isdigit():
            print("Enter a positive integer.")
            continue
        count = int(value)
        if count <= 0:
            print("Thread count must be positive.")
            continue
        return count


def prompt_ports() -> Set[int]:
    while True:
        value = input("Enter ports separated by commas (for example, 80 or 80,443,8080): ").strip()
        if not value:
            print("The list of ports cannot be empty. Try again.")
            continue
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if not parts:
            print("The list of ports cannot be empty. Try again.")
            continue
        ports: Set[int] = set()
        invalid_parts: List[str] = []
        for part in parts:
            if not part.isdigit():
                invalid_parts.append(part)
                continue
            port = int(part)
            if not (1 <= port <= 65535):
                invalid_parts.append(part)
                continue
            ports.add(port)
        if invalid_parts:
            print("Invalid ports: " + ", ".join(invalid_parts) + ". Try again.")
            continue
        return ports


def prompt_site_title() -> str:
    while True:
        value = input("Enter the expected site title: ").strip()
        if not value:
            print("The site title cannot be empty. Try again.")
            continue
        return value


def merge_targets(base_targets: Dict[str, Set[int]], extra_ports: Iterable[int]) -> Iterable[Target]:
    extra_ports_set = set(extra_ports)
    for ip, ports in base_targets.items():
        all_ports = set(ports)
        all_ports.update(extra_ports_set)
        if not all_ports:
            print(f"No ports specified for IP {ip}. Skipping.")
            continue
        for port in sorted(all_ports):
            yield Target(ip=ip, port=port)


def _schemes_for_port(port: int) -> Tuple[str, ...]:
    """Return the network schemes that should be checked for a port."""

    if port == 443:
        return ("https", "http")
    return ("http",)


def check_target(target: Target, expected_title: str) -> List[Tuple[str, bool, str]]:
    results: List[Tuple[str, bool, str]] = []
    normalized_expected = normalize_title(expected_title)

    for scheme in _schemes_for_port(target.port):
        body: bytes = b""
        content_type: Optional[str] = None
        success = False
        last_exception: Optional[Exception] = None

        for attempt in range(1, REQUEST_ATTEMPTS + 1):
            connection: Optional[http.client.HTTPConnection] = None
            response: Optional[http.client.HTTPResponse] = None
            try:
                if scheme == "http":
                    connection = http.client.HTTPConnection(
                        target.ip, target.port, timeout=REQUEST_TIMEOUT
                    )
                else:
                    context = ssl._create_unverified_context()
                    connection = http.client.HTTPSConnection(
                        target.ip, target.port, timeout=REQUEST_TIMEOUT, context=context
                    )

                connection.request(
                    "GET",
                    "/",
                    headers={
                        "User-Agent": USER_AGENT,
                        "Host": target.ip,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Connection": "close",
                    },
                )
                response = connection.getresponse()
                content_type = response.getheader("Content-Type")
                body = response.read(READ_LIMIT)
                success = True
                break
            except Exception as exc:
                last_exception = exc
                if attempt < REQUEST_ATTEMPTS:
                    LOGGER.debug(
                        "%s: %s attempt %d failed, retrying",
                        target,
                        scheme,
                        attempt,
                        exc_info=True,
                    )
                else:
                    LOGGER.warning(
                        "%s: %s request failed after %d attempts",
                        target,
                        scheme,
                        REQUEST_ATTEMPTS,
                        exc_info=True,
                    )
            finally:
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        LOGGER.debug(
                            "%s: error closing response", target, exc_info=True
                        )
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        LOGGER.debug(
                            "%s: error closing connection", target, exc_info=True
                        )

        if not success:
            error_message = (
                f"request error after {REQUEST_ATTEMPTS} attempts: {last_exception}"
                if last_exception
                else "request error"
            )
            results.append((scheme, False, error_message))
            continue

        text = decode_body(body, content_type)
        title = extract_title(text)
        if title is None:
            results.append((scheme, False, "title not found"))
            continue

        matches = title == normalized_expected
        if matches:
            message = f"match (title: '{title}')"
        else:
            message = (
                f"title '{title}' does not match expected '{normalized_expected}'"
            )
        results.append((scheme, matches, message))

    return results


def decode_body(body: bytes, content_type: Optional[str]) -> str:
    encoding = "utf-8"
    if content_type:
        match = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
        if match:
            encoding = match.group(1).lower()
    try:
        return body.decode(encoding, errors="ignore")
    except LookupError:
        return body.decode("utf-8", errors="ignore")


def extract_title(html_text: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = html.unescape(match.group(1))
    return normalize_title(title)


def normalize_title(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def save_matched_ip(
    output_path: Path, ip: str, seen_ips: Set[str], lock: Lock
) -> None:
    with lock:
        if ip in seen_ips:
            return

        with output_path.open("a", encoding="utf-8") as handle:
            handle.write(f"{ip}\n")
        seen_ips.add(ip)


def _drain_completed(
    futures: Dict[Future[List[Tuple[str, bool, str]]], Target],
    output_path: Path,
    matched_ips: Set[str],
    lock: Lock,
    *,
    wait_for_one: bool,
) -> int:
    if not futures:
        return 0

    if wait_for_one:
        done, _ = wait(futures.keys(), return_when=FIRST_COMPLETED)
    else:
        done = {future for future in futures if future.done()}
        if not done:
            return 0

    processed = 0
    for future in done:
        target = futures.pop(future)
        try:
            check_results = future.result()
        except Exception:
            LOGGER.exception("%s: unexpected error", target)
            continue

        has_match = False

        for scheme, is_match, message in check_results:
            status = "OK" if is_match else "FAIL"
            log_message = f"[{scheme.upper()}] {target}: {status} — {message}"
            if is_match:
                has_match = True
                LOGGER.info(log_message)
            else:
                LOGGER.warning(log_message)

        if has_match:
            save_matched_ip(output_path, target.ip, matched_ips, lock)
            LOGGER.info("IP %s saved to %s", target.ip, output_path)
        else:
            LOGGER.debug("Results for %s recorded in %s", target, output_path)
        processed += 1

    return processed


def _compute_max_pending(thread_count: int) -> int:
    # Conservative queue cap: keep at least 64 tasks, but no more than 2×pool or 512.
    return max(64, min(thread_count * 2, 512))


def process_targets(
    targets: Iterable[Target],
    thread_count: int,
    expected_title: str,
    output_path: Path,
) -> int:
    total_processed = 0
    max_pending = _compute_max_pending(thread_count)
    matched_ips: Set[str] = set()
    file_lock = Lock()

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures: Dict[Future[List[Tuple[str, bool, str]]], Target] = {}

        for target in targets:
            # Even though each request closes its connection, a large number of
            # in-flight attempts will still hold descriptors until they time out.
            # Throttle submissions so we do not exceed the safe descriptor budget.
            while len(futures) >= max_pending:
                total_processed += _drain_completed(
                    futures,
                    output_path,
                    matched_ips,
                    file_lock,
                    wait_for_one=True,
                )

            future = executor.submit(check_target, target, expected_title)
            futures[future] = target

            total_processed += _drain_completed(
                futures,
                output_path,
                matched_ips,
                file_lock,
                wait_for_one=False,
            )

        while futures:
            total_processed += _drain_completed(
                futures,
                output_path,
                matched_ips,
                file_lock,
                wait_for_one=True,
            )

    return total_processed


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_path = prompt_file_path()
    loaded_targets = load_targets_from_file(file_path)
    thread_count = prompt_thread_count()
    ports = prompt_ports()
    expected_title = prompt_site_title()

    output_path = Path("output.txt")
    output_path.touch(exist_ok=True)

    targets_iter = iter(merge_targets(loaded_targets, ports))
    try:
        first_target = next(targets_iter)
    except StopIteration:
        message = "No targets to check. Exiting."
        print(message)
        output_path.write_text(message + "\n", encoding="utf-8")
        LOGGER.info(message)
        return

    all_targets = chain([first_target], targets_iter)
    output_path.write_text("", encoding="utf-8")
    LOGGER.info("Starting target checks...")
    total_processed = process_targets(all_targets, thread_count, expected_title, output_path)
    LOGGER.info("Total targets checked: %d", total_processed)


if __name__ == "__main__":
    main()
