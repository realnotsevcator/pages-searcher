#!/usr/bin/env python3
from __future__ import annotations

import html
import http.client
import re
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

USER_AGENT = "Mozilla/5.0 (compatible; SiteTitleChecker/1.0)"
READ_LIMIT = 65536
REQUEST_TIMEOUT = 5


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


def merge_targets(base_targets: Dict[str, Set[int]], extra_ports: Iterable[int]) -> List[Target]:
    targets: List[Target] = []
    extra_ports_set = set(extra_ports)
    for ip, ports in base_targets.items():
        all_ports = set(ports)
        all_ports.update(extra_ports_set)
        if not all_ports:
            print(f"No ports specified for IP {ip}. Skipping.")
            continue
        for port in sorted(all_ports):
            targets.append(Target(ip=ip, port=port))
    return targets


def check_target(target: Target, expected_title: str) -> List[Tuple[str, bool, str]]:
    results: List[Tuple[str, bool, str]] = []
    for scheme in ("http", "https"):
        try:
            if scheme == "http":
                connection: http.client.HTTPConnection = http.client.HTTPConnection(
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
                },
            )
            response = connection.getresponse()
            content_type = response.getheader("Content-Type")
            body = response.read(READ_LIMIT)
            connection.close()
        except Exception as exc:
            results.append((scheme, False, f"request error: {exc}"))
            continue

        text = decode_body(body, content_type)
        title = extract_title(text)
        if title is None:
            results.append((scheme, False, "title not found"))
            continue
        matches = title.strip() == expected_title.strip()
        if matches:
            results.append((scheme, True, f"match (title: '{title.strip()}')"))
        else:
            results.append((scheme, False, f"title '{title.strip()}' does not match"))
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
    title = html.unescape(match.group(1)).strip()
    return re.sub(r"\s+", " ", title)


def main() -> None:
    file_path = prompt_file_path()
    loaded_targets = load_targets_from_file(file_path)
    thread_count = prompt_thread_count()
    ports = prompt_ports()
    expected_title = prompt_site_title()

    targets = merge_targets(loaded_targets, ports)
    if not targets:
        print("No targets to check. Exiting.")
        return

    output_path = Path("output.txt")
    output_path.write_text("", encoding="utf-8")
    recorded_ips: Set[str] = set()

    print(f"Total targets to check: {len(targets)}")
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        future_to_target = {
            executor.submit(check_target, target, expected_title): target
            for target in targets
        }
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                check_results = future.result()
            except Exception as exc:
                print(f"{target}: unexpected error: {exc}")
                continue
            for scheme, is_match, message in check_results:
                status = "OK" if is_match else "FAIL"
                print(f"[{scheme.upper()}] {target}: {status} — {message}")

            has_http_or_https = any(
                not message.lower().startswith("request error:") for _, _, message in check_results
            )
            if has_http_or_https and target.ip not in recorded_ips:
                recorded_ips.add(target.ip)
                with output_path.open("a", encoding="utf-8") as handle:
                    handle.write(f"{target.ip}\n")


if __name__ == "__main__":
    main()
