#!/usr/bin/env python3
from __future__ import annotations

import codecs
import csv
import html
import http.client
import importlib.util
import logging
import re
import ssl
from encodings import aliases
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

CHARSET_NORMALIZER_AVAILABLE = (
    importlib.util.find_spec("charset_normalizer") is not None
)
if CHARSET_NORMALIZER_AVAILABLE:
    from charset_normalizer import from_bytes as _normalize_from_bytes
else:
    _normalize_from_bytes = None

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
    for line_number, raw_line in enumerate(_read_lines_any_encoding(path), start=1):
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


@dataclass(frozen=True)
class MatchRule:
    pattern: str
    mode: str  # exact, prefix, substring, substring_ci

    def matches(self, title: str) -> bool:
        if self.mode == "exact":
            return title == self.pattern
        if self.mode == "prefix":
            return title.startswith(self.pattern)
        if self.mode == "substring":
            return self.pattern in title
        if self.mode == "substring_ci":
            return self.pattern.lower() in title.lower()
        return False


@dataclass(frozen=True)
class MatchResult:
    scheme: str
    is_match: bool
    message: str
    title: Optional[str]


def check_target(target: Target, rules: List[MatchRule]) -> List[MatchResult]:
    results: List[MatchResult] = []

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
            results.append(
                MatchResult(scheme=scheme, is_match=False, message=error_message, title=None)
            )
            continue

        text = decode_body(body, content_type)
        title = extract_title(text)
        if title is None:
            results.append(
                MatchResult(scheme=scheme, is_match=False, message="title not found", title=None)
            )
            continue

        normalized_title = normalize_title(title)
        is_match = any(rule.matches(normalized_title) for rule in rules)
        message = (
            f"match (title: '{normalized_title}')"
            if is_match
            else "title does not match any rule"
        )
        results.append(
            MatchResult(
                scheme=scheme,
                is_match=is_match,
                message=message,
                title=normalized_title,
            )
        )

    return results


def _detect_bom_encoding(data: bytes) -> Optional[str]:
    bom_map = {
        codecs.BOM_UTF8: "utf-8-sig",
        codecs.BOM_UTF16_LE: "utf-16-le",
        codecs.BOM_UTF16_BE: "utf-16-be",
        codecs.BOM_UTF32_LE: "utf-32-le",
        codecs.BOM_UTF32_BE: "utf-32-be",
    }
    for bom, encoding in bom_map.items():
        if data.startswith(bom):
            return encoding
    return None


def _decode_with_all_encodings(
    data: bytes, preferred_encodings: Iterable[str]
) -> str:
    tried: Set[str] = set()

    bom_encoding = _detect_bom_encoding(data)
    if bom_encoding:
        try:
            return data.decode(bom_encoding)
        except UnicodeDecodeError:
            tried.add(bom_encoding)

    for encoding in preferred_encodings:
        normalized = encoding.lower()
        if normalized in tried:
            continue
        tried.add(normalized)
        try:
            return data.decode(normalized)
        except (LookupError, UnicodeDecodeError):
            continue

    if _normalize_from_bytes is not None:
        normalized_result = _normalize_from_bytes(data).best()
        if normalized_result is not None:
            return str(normalized_result)

    for encoding in sorted(set(aliases.aliases.values())):
        normalized = encoding.lower()
        if normalized in tried:
            continue
        tried.add(normalized)
        try:
            return data.decode(normalized)
        except (LookupError, UnicodeDecodeError):
            continue

    return data.decode("utf-8", errors="replace")


def decode_body(body: bytes, content_type: Optional[str]) -> str:
    preferred_encodings: List[str] = []
    if content_type:
        match = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
        if match:
            preferred_encodings.append(match.group(1).lower())

    head_fragment = body[:16384].decode("ascii", errors="ignore")
    meta_match = re.search(r"charset=['\"]?([\w-]+)", head_fragment, re.IGNORECASE)
    if meta_match:
        preferred_encodings.append(meta_match.group(1).lower())

    preferred_encodings.append("utf-8")

    return _decode_with_all_encodings(body, preferred_encodings)


def extract_title(html_text: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>(.*?)</title>", html_text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = html.unescape(match.group(1))
    return normalize_title(title)


def normalize_title(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _read_lines_any_encoding(path: Path) -> List[str]:
    raw_bytes = path.read_bytes()
    text = _decode_with_all_encodings(raw_bytes, ["utf-8"])
    return text.splitlines()


def load_ips(path: Path) -> List[str]:
    ips: List[str] = []
    for line_number, raw_line in enumerate(_read_lines_any_encoding(path), start=1):
        ip = raw_line.strip()
        if not ip or ip.startswith("#"):
            continue
        ips.append(ip)
    return ips


def load_ports(path: Path) -> List[int]:
    ports: List[int] = []
    for line_number, raw_line in enumerate(_read_lines_any_encoding(path), start=1):
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        if not value.isdigit():
            LOGGER.warning("Line %d in %s has invalid port '%s'", line_number, path, value)
            continue
        port = int(value)
        if 1 <= port <= 65535:
            ports.append(port)
        else:
            LOGGER.warning(
                "Line %d in %s has port outside valid range: '%s'", line_number, path, value
            )
    return ports


def _parse_rule_line(raw_line: str) -> Optional[MatchRule]:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None

    if line.startswith("**") and line.endswith("**") and len(line) > 4:
        return MatchRule(pattern=normalize_title(line[2:-2]), mode="substring_ci")
    if line.startswith("*") and line.endswith("*") and len(line) > 2:
        return MatchRule(pattern=normalize_title(line[1:-1]), mode="substring")
    if line.endswith("=") and len(line) > 1:
        return MatchRule(pattern=normalize_title(line[:-1]), mode="prefix")
    return MatchRule(pattern=normalize_title(line), mode="exact")


def load_match_rules(path: Path) -> List[MatchRule]:
    rules: List[MatchRule] = []
    for line_number, raw_line in enumerate(_read_lines_any_encoding(path), start=1):
        rule = _parse_rule_line(raw_line)
        if rule:
            rules.append(rule)
        else:
            LOGGER.debug("Line %d in %s ignored", line_number, path)
    return rules


@dataclass
class OutputManager:
    output_ip: Path
    output_ip_port: Path
    output_ip_port_title: Path
    output_csv: Path
    seen_ips: Set[str]
    seen_ip_ports: Set[str]
    seen_ip_port_titles: Set[str]
    csv_writer: csv.writer
    csv_file: Any
    lock: Lock

    @classmethod
    def create(cls) -> "OutputManager":
        output_ip = Path("output.txt")
        output_ip_port = Path("output_v2.txt")
        output_ip_port_title = Path("output_v3.txt")
        output_csv = Path("output.csv")

        for path in (output_ip, output_ip_port, output_ip_port_title):
            path.write_text("", encoding="utf-8")

        csv_file = output_csv.open("w", encoding="utf-8", newline="")
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["Link", "IP", "Port", "Name of page"])

        return cls(
            output_ip=output_ip,
            output_ip_port=output_ip_port,
            output_ip_port_title=output_ip_port_title,
            output_csv=output_csv,
            seen_ips=set(),
            seen_ip_ports=set(),
            seen_ip_port_titles=set(),
            csv_writer=csv_writer,
            csv_file=csv_file,
            lock=Lock(),
        )

    def close(self) -> None:
        with self.lock:
            self.csv_file.close()

    def record_match(self, target: Target, scheme: str, title: str) -> None:
        with self.lock:
            if target.ip not in self.seen_ips:
                with self.output_ip.open("a", encoding="utf-8") as handle:
                    handle.write(f"{target.ip}\n")
                self.seen_ips.add(target.ip)

            ip_port = f"{target.ip}:{target.port}"
            if ip_port not in self.seen_ip_ports:
                with self.output_ip_port.open("a", encoding="utf-8") as handle:
                    handle.write(f"{ip_port}\n")
                self.seen_ip_ports.add(ip_port)

            ip_port_title = f"{ip_port}@{title}"
            if ip_port_title not in self.seen_ip_port_titles:
                with self.output_ip_port_title.open("a", encoding="utf-8") as handle:
                    handle.write(f"{ip_port_title}\n")
                self.seen_ip_port_titles.add(ip_port_title)

            link = f"{scheme}://{ip_port}/"
            self.csv_writer.writerow([link, target.ip, target.port, title])


def _drain_completed(
    futures: Dict[Future[List[MatchResult]], Target],
    outputs: OutputManager,
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

        for result in check_results:
            status = "OK" if result.is_match else "FAIL"
            log_message = f"[{result.scheme.upper()}] {target}: {status} — {result.message}"
            if result.is_match and result.title:
                has_match = True
                outputs.record_match(target, result.scheme, result.title)
                LOGGER.info(log_message)
            else:
                LOGGER.warning(log_message)

        if not has_match:
            LOGGER.debug("Results for %s recorded without matches", target)
        processed += 1

    return processed


def _compute_max_pending(thread_count: int) -> int:
    # Conservative queue cap: keep at least 64 tasks, but no more than 2×pool or 512.
    return max(64, min(thread_count * 2, 512))


def process_targets(
    targets: Iterable[Target],
    thread_count: int,
    rules: List[MatchRule],
    outputs: OutputManager,
) -> int:
    total_processed = 0
    max_pending = _compute_max_pending(thread_count)

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures: Dict[Future[List[MatchResult]], Target] = {}

        for target in targets:
            # Even though each request closes its connection, a large number of
            # in-flight attempts will still hold descriptors until they time out.
            # Throttle submissions so we do not exceed the safe descriptor budget.
            while len(futures) >= max_pending:
                total_processed += _drain_completed(
                    futures,
                    outputs,
                    wait_for_one=True,
                )

            future = executor.submit(check_target, target, rules)
            futures[future] = target

            total_processed += _drain_completed(
                futures,
                outputs,
                wait_for_one=False,
            )

        while futures:
            total_processed += _drain_completed(
                futures,
                outputs,
                wait_for_one=True,
            )

    return total_processed


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    ips_path = Path("ips.txt")
    ports_path = Path("ports.txt")
    matches_path = Path("matches.txt")

    for required_path in (ips_path, ports_path, matches_path):
        if not required_path.is_file():
            print(f"Required file not found: {required_path}")
            return

    ips = load_ips(ips_path)
    ports = load_ports(ports_path)
    rules = load_match_rules(matches_path)

    if not ips:
        print("No IP addresses found in ips.txt. Exiting.")
        return
    if not ports:
        print("No ports found in ports.txt. Exiting.")
        return
    if not rules:
        print("No match rules found in matches.txt. Exiting.")
        return

    thread_count = prompt_thread_count()
    outputs = OutputManager.create()

    try:
        targets = [Target(ip=ip, port=port) for ip in ips for port in ports]
        if not targets:
            print("No targets to check. Exiting.")
            return

        LOGGER.info("Starting target checks...")
        total_processed = process_targets(targets, thread_count, rules, outputs)
        LOGGER.info("Total targets checked: %d", total_processed)
    finally:
        outputs.close()


if __name__ == "__main__":
    main()
