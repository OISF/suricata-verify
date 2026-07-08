#!/usr/bin/env python3
"""Generate per-test meta.yaml protocol lists from pcaps.

The protocol list is derived from tshark's per-frame dissector stack and then
mapped to Suricata-style app-layer protocol names where the names differ.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable

import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]

# tshark dissector names that should be normalized or expanded for metadata.
# Values can be either a string or a list of strings. Protocols not listed here
# are emitted as tshark reports them, unless they are in IGNORED_PROTOCOLS.
PROTOCOL_RENAMES = {
    "bittorrent_dht": "bittorrent-dht",
    "bootp": "dhcp",
    "btdht": "bittorrent-dht",
    "cip": "enip",
    "cldap": "ldap",
    "dcerpc.cn": "dcerpc",
    "dcerpc.dg": "dcerpc",
    "dhcpv6": ["dhcp", "dhcpv6"],
    "ftp_data": "ftp-data",
    "gquic": "quic",
    "ikev2": "ike",
    "imf": "smtp",
    "isakmp": "ike",
    "kerberos": "krb5",
    "mbtcp": "modbus",
    "pop": "pop3",
    "postgresql": "pgsql",
    "smb2": "smb",
    "ssl": "tls",
    "vnc": "rfb",
    "xmpp": ["xmpp", "jabber"],
    "x509ce": ["x509", "x509ce"],
    "x509sat": ["x509", "x509sat"],
}

# Keep this minimal: the metadata is intentionally a liberal list of protocols
# tshark reports for the pcap, with only PROTOCOL_RENAMES applied. "ethertype"
# is just Wireshark's Ethernet dispatch field and adds noise.
IGNORED_PROTOCOLS = {"ethertype"}

PCAP_REF_RE = re.compile(
    r"(?P<path>(?:\$\{TEST_DIR\}|\$TEST_DIR|[^\s\"'`])+?\.pcap(?:ng)?)"
)


class FlowStyleList(list):
    pass


class MetaDumper(yaml.SafeDumper):
    pass


def represent_flow_style_list(dumper: yaml.SafeDumper, data: FlowStyleList):
    return dumper.represent_sequence(
        "tag:yaml.org,2002:seq", list(data), flow_style=True
    )


MetaDumper.add_representer(FlowStyleList, represent_flow_style_list)


def load_yaml(path: Path) -> dict:
    with path.open("rb") as fp:
        data = yaml.safe_load(fp) or {}
    if not isinstance(data, dict):
        return {}
    return data


def resolve_command_ref(test_dir: Path, ref: str) -> Path:
    ref = ref.replace("${TEST_DIR}", str(test_dir))
    ref = ref.replace("$TEST_DIR", str(test_dir))
    path = Path(ref)
    if not path.is_absolute():
        path = test_dir / path
    return path.resolve()


def unique_paths(paths: Iterable[Path]) -> list[Path]:
    seen = set()
    unique = []
    for path in paths:
        if path not in seen:
            unique.append(path)
            seen.add(path)
    return unique


def relative_to_repo(path: Path) -> Path:
    try:
        return path.relative_to(REPO_ROOT)
    except ValueError:
        return path


def find_pcaps(test_yaml: Path) -> tuple[list[Path], list[str]]:
    config = load_yaml(test_yaml)
    test_dir = test_yaml.parent
    warnings = []
    pcaps = []

    if config.get("pcap") is False:
        return [], warnings

    pcap_value = config.get("pcap")
    if isinstance(pcap_value, str):
        pcaps.append((test_dir / pcap_value).resolve())
    elif pcap_value is not None:
        warnings.append(f"{test_yaml}: unsupported pcap value: {pcap_value!r}")
    else:
        command = config.get("command")
        if command:
            for match in PCAP_REF_RE.finditer(str(command)):
                pcaps.append(resolve_command_ref(test_dir, match.group("path")))
        if not pcaps:
            pcaps.extend(sorted(path.resolve() for path in test_dir.glob("*.pcap")))
            pcaps.extend(sorted(path.resolve() for path in test_dir.glob("*.pcapng")))

    existing = []
    for pcap in unique_paths(pcaps):
        if pcap.exists():
            existing.append(pcap)
        else:
            warnings.append(f"{test_yaml}: pcap not found: {pcap}")
    return existing, warnings


def sort_protocols(protocols: Iterable[str]) -> list[str]:
    return sorted(set(protocols))


def protocols_from_tshark_output(output: str) -> list[str]:
    protocols = set()
    for line in output.splitlines():
        stack = [proto.lower() for proto in line.strip().split(":") if proto]
        if not stack:
            continue

        for proto in stack:
            if proto in IGNORED_PROTOCOLS:
                continue
            replacement = PROTOCOL_RENAMES.get(proto, proto)
            if isinstance(replacement, list):
                protocols.update(replacement)
            else:
                protocols.add(replacement)

    return sort_protocols(protocols)


def extract_pcap_protocols(pcap: Path) -> tuple[Path, list[str], str | None]:
    result = subprocess.run(
        ["tshark", "-n", "-r", str(pcap), "-T", "fields", "-e", "frame.protocols"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    protocols = protocols_from_tshark_output(result.stdout)
    if result.returncode != 0 and not result.stdout:
        error = result.stderr.strip() or f"tshark exited with {result.returncode}"
        return pcap, protocols, error
    return pcap, protocols, None


def render_meta(path: Path, protocols: list[str]) -> str:
    meta = {}
    if path.exists():
        meta = load_yaml(path)
    meta["protocols"] = FlowStyleList(protocols)
    return yaml.dump(meta, Dumper=MetaDumper, sort_keys=False, width=4096)


def write_meta(path: Path, content: str, *, dry_run: bool, check: bool) -> bool:
    old = path.read_text() if path.exists() else None
    if old == content:
        return False
    if check or dry_run:
        return True
    path.write_text(content)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate meta.yaml protocols from test pcaps."
    )
    parser.add_argument(
        "test_dir",
        nargs="?",
        type=Path,
        help="optional single test directory containing test.yaml to update",
    )
    parser.add_argument(
        "--tests-root",
        type=Path,
        default=REPO_ROOT / "tests",
        help="root directory to scan for test.yaml files",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=min(8, os.cpu_count() or 1),
        help="number of concurrent tshark processes",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would change without writing files",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any meta.yaml would change",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print each changed meta.yaml path",
    )
    args = parser.parse_args()

    if args.test_dir:
        test_dir = args.test_dir.resolve()
        test_yaml = test_dir / "test.yaml"
        if not test_yaml.exists():
            parser.error(f"{args.test_dir} does not contain test.yaml")
        test_yamls = [test_yaml]
    else:
        tests_root = args.tests_root.resolve()
        test_yamls = sorted(tests_root.rglob("test.yaml"))

    test_pcaps = {}
    pcap_tests = {}
    warnings = []
    printed_tests = set()

    def print_test_progress(test_yaml: Path) -> None:
        if test_yaml in printed_tests:
            return
        print(relative_to_repo(test_yaml.parent), file=sys.stderr, flush=True)
        printed_tests.add(test_yaml)

    for test_yaml in test_yamls:
        pcaps, pcap_warnings = find_pcaps(test_yaml)
        test_pcaps[test_yaml] = pcaps
        if pcaps:
            for pcap in pcaps:
                pcap_tests.setdefault(pcap, []).append(test_yaml)
        else:
            print_test_progress(test_yaml)
        warnings.extend(pcap_warnings)

    unique_pcaps = sorted({pcap for pcaps in test_pcaps.values() for pcap in pcaps})
    pcap_protocols = {}
    tshark_errors = []

    if unique_pcaps:
        jobs = max(1, args.jobs)
        with ThreadPoolExecutor(max_workers=jobs) as executor:
            futures = {
                executor.submit(extract_pcap_protocols, pcap): pcap
                for pcap in unique_pcaps
            }
            for future in as_completed(futures):
                pcap, protocols, error = future.result()
                pcap_protocols[pcap] = protocols
                for test_yaml in pcap_tests.get(pcap, []):
                    print_test_progress(test_yaml)
                if error:
                    tshark_errors.append(f"{pcap}: {error}")

    changed = 0
    empty = 0
    for test_yaml in test_yamls:
        print_test_progress(test_yaml)
        protocols = sort_protocols(
            proto
            for pcap in test_pcaps[test_yaml]
            for proto in pcap_protocols.get(pcap, [])
        )
        if not protocols:
            empty += 1
        meta_yaml = test_yaml.parent / "meta.yaml"
        content = render_meta(meta_yaml, protocols)
        if write_meta(meta_yaml, content, dry_run=args.dry_run, check=args.check):
            changed += 1
            if args.verbose or args.dry_run or args.check:
                print(meta_yaml.relative_to(REPO_ROOT))

    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)
    for error in tshark_errors:
        print(f"warning: {error}", file=sys.stderr)

    print(
        "tests={} tests_with_pcaps={} unique_pcaps={} changed={} empty={}".format(
            len(test_yamls),
            sum(1 for pcaps in test_pcaps.values() if pcaps),
            len(unique_pcaps),
            changed,
            empty,
        )
    )

    if args.check and changed:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
