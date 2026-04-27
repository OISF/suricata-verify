#!/usr/bin/env python3

# Script to prepare live IPS namespace labs for Suricata testing.

import argparse
import glob
import json
import os
import platform
import re
import shlex
import signal
import string
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import namedtuple
from dataclasses import dataclass
from typing import IO

import yaml

CLIENT_NS = "client"
SERVER_NS = "server"
DUT_NS = "dut"

MTU = "1500"

CLIENT_IF = "client"
SERVER_IF = "server"
DUT_CLIENT_IF = "client0"
DUT_SERVER_IF = "server0"
DUT_BRIDGE_IF = "br0"

TMP_CLIENT_IF = "ptp-client"
TMP_SERVER_IF = "ptp-server"
TMP_DUT_CLIENT_IF = "ptp-client0"
TMP_DUT_SERVER_IF = "ptp-server0"

AFP_CLIENT_IP = "10.200.0.2/24"
AFP_SERVER_IP = "10.200.0.1/24"

NFQ_CLIENT_IP = "10.200.1.2/24"
NFQ_DUT_CLIENT_IP = "10.200.1.254/24"
NFQ_SERVER_IP = "10.200.0.1/24"
NFQ_DUT_SERVER_IP = "10.200.0.254/24"
NFQ_CLIENT_GW = "10.200.1.254"
NFQ_SERVER_GW = "10.200.0.254"
NFQ_QUEUE_NUM = "0"

ALL_NAMESPACES = (CLIENT_NS, SERVER_NS, DUT_NS)
ROOT_LINKS = (TMP_CLIENT_IF, TMP_SERVER_IF, TMP_DUT_CLIENT_IF, TMP_DUT_SERVER_IF)
MODES = ("afp", "ids", "nfq")

MODE_LABELS = {
    "ids": "IDS",
    "afp": "AF_PACKET",
    "nfq": "NFQ",
}

verbose = False
suricata_config_cache = {}


def configure_script_env() -> None:
    """Expose helper binaries to client/server scripts via environment variables."""
    cwd = os.getcwd()
    candidates = [
        os.path.join(cwd, "rust", "target", "debug", "suricatasc"),
        os.path.join(cwd, "rust", "target", "release", "suricatasc"),
    ]
    for candidate in candidates:
        if os.path.isfile(candidate):
            os.environ["SURICATASC"] = os.path.realpath(candidate)
            return
    os.environ.pop("SURICATASC", None)


def load_markdown_frontmatter(path: str) -> dict:
    """Load YAML (---) frontmatter from a Markdown file."""
    if not os.path.isfile(path):
        return {}

    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()

    if not lines or lines[0].strip() != "---":
        return {}

    body = []
    for line in lines[1:]:
        if line.strip() == "---":
            raw = "\n".join(body)
            data = yaml.safe_load(raw) or {}
            if not isinstance(data, dict):
                raise ValueError(f"{path}: frontmatter must be a mapping")
            return data
        body.append(line)

    raise ValueError(f"{path}: unterminated frontmatter")


def get_test_tags(test_dir: str) -> set[str]:
    """Return normalized tags from a test README frontmatter."""
    readme_path = None
    for candidate in ("README.md", "readme.md"):
        path = os.path.join(test_dir, candidate)
        if os.path.isfile(path):
            readme_path = path
            break

    if readme_path is None:
        return set()

    frontmatter = load_markdown_frontmatter(readme_path)
    tags = frontmatter.get("tags", [])
    if tags is None:
        return set()
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError(
            f"{readme_path}: frontmatter 'tags' must be a string or list of strings"
        )
    return {tag.strip().lower() for tag in tags if tag.strip()}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Live IPS namespace lab manager for Suricata testing",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show Suricata stdout/stderr output",
    )

    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="run all tests")
    run_parser.add_argument(
        "--mode",
        choices=list(MODES),
        help="only run tests for this mode",
    )
    run_parser.add_argument(
        "--tag",
        action="append",
        default=[],
        metavar="TAG",
        help="only run tests whose README.md frontmatter tags include TAG; may be specified multiple times",
    )
    run_parser.add_argument(
        "substring",
        nargs="?",
        help="only run tests whose name contains this substring",
    )

    for mode_name in MODES:
        label = MODE_LABELS.get(mode_name, mode_name)
        mode_parser = subparsers.add_parser(mode_name, help=f"{label} mode")
        action_sub = mode_parser.add_subparsers(dest="action")
        action_sub.add_parser("up", help="bring lab up")
        action_sub.add_parser("down", help="tear lab down")
        action_sub.add_parser("status", help="show lab status")
        shell_p = action_sub.add_parser("shell", help="open shell in namespace")
        shell_p.add_argument(
            "target",
            nargs="?",
            default="client",
            choices=["client", "server", "dut"],
        )

    return parser


def need_root() -> None:
    if os.geteuid() == 0:
        return
    print(
        "ERROR: this script must be run as root. Use: sudo run.py ...",
        file=sys.stderr,
    )
    sys.exit(1)


def need_cmd(cmd: str) -> None:
    if shutil.which(cmd) is None:
        print(f"ERROR: missing command: {cmd}", file=sys.stderr)
        sys.exit(1)


def run(
    cmd: list[str], *, quiet: bool = False, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, object] = {
        "check": True,
        "text": True,
    }
    if quiet:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    elif capture:
        kwargs["capture_output"] = True
    return subprocess.run(cmd, **kwargs)


def run_quiet(cmd: list[str]) -> None:
    subprocess.run(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    )


def show(cmd: list[str]) -> None:
    subprocess.run(cmd, check=False)


def ns_exec(
    ns: str, cmd: list[str], *, quiet: bool = False, capture: bool = False
) -> subprocess.CompletedProcess[str]:
    return run(["ip", "netns", "exec", ns, *cmd], quiet=quiet, capture=capture)


def ns_run_quiet(ns: str, cmd: list[str]) -> None:
    run_quiet(["ip", "netns", "exec", ns, *cmd])


def ns_show(ns: str, cmd: list[str]) -> None:
    show(["ip", "netns", "exec", ns, *cmd])


def netns_exists(ns: str) -> bool:
    result = run(["ip", "netns", "list"], capture=True)
    for line in result.stdout.splitlines():
        parts = line.split()
        if parts and parts[0] == ns:
            return True
    return False


def kill_ns_processes(ns: str) -> None:
    if not netns_exists(ns):
        return

    result = run(["ip", "netns", "pids", ns], capture=True)
    pids = [pid for pid in result.stdout.split() if pid.isdigit()]
    if not pids:
        return

    run_quiet(["kill", *pids])
    time.sleep(0.1)

    result = run(["ip", "netns", "pids", ns], capture=True)
    pids = [pid for pid in result.stdout.split() if pid.isdigit()]
    if pids:
        run_quiet(["kill", "-9", *pids])


def disable_offloads(ns: str, iface: str) -> None:
    for feature in ("rx", "tx", "tso", "gro", "lro", "gso", "sg", "rxvlan", "txvlan"):
        ns_run_quiet(ns, ["ethtool", "-K", iface, feature, "off"])


def setup_namespaces() -> None:
    for ns in ALL_NAMESPACES:
        run(["ip", "netns", "add", ns])
        run(["ip", "-n", ns, "link", "set", "lo", "up"])
        ns_exec(
            ns, ["sysctl", "-w", "net.ipv4.ping_group_range=0 2147483647"], quiet=True
        )


def setup_links() -> None:
    run(
        [
            "ip",
            "link",
            "add",
            TMP_CLIENT_IF,
            "type",
            "veth",
            "peer",
            "name",
            TMP_DUT_CLIENT_IF,
        ]
    )
    run(
        [
            "ip",
            "link",
            "add",
            TMP_SERVER_IF,
            "type",
            "veth",
            "peer",
            "name",
            TMP_DUT_SERVER_IF,
        ]
    )

    run(["ip", "link", "set", TMP_CLIENT_IF, "netns", CLIENT_NS])
    run(["ip", "link", "set", TMP_SERVER_IF, "netns", SERVER_NS])
    run(["ip", "link", "set", TMP_DUT_CLIENT_IF, "netns", DUT_NS])
    run(["ip", "link", "set", TMP_DUT_SERVER_IF, "netns", DUT_NS])

    run(["ip", "-n", CLIENT_NS, "link", "set", TMP_CLIENT_IF, "name", CLIENT_IF])
    run(["ip", "-n", SERVER_NS, "link", "set", TMP_SERVER_IF, "name", SERVER_IF])
    run(["ip", "-n", DUT_NS, "link", "set", TMP_DUT_CLIENT_IF, "name", DUT_CLIENT_IF])
    run(["ip", "-n", DUT_NS, "link", "set", TMP_DUT_SERVER_IF, "name", DUT_SERVER_IF])

    for ns, iface in (
        (CLIENT_NS, CLIENT_IF),
        (SERVER_NS, SERVER_IF),
        (DUT_NS, DUT_CLIENT_IF),
        (DUT_NS, DUT_SERVER_IF),
    ):
        run(["ip", "-n", ns, "link", "set", iface, "mtu", MTU])


def bring_up_interface(ns: str, iface: str) -> None:
    disable_offloads(ns, iface)
    ns_exec(ns, ["ip", "link", "set", iface, "up"])


def add_address(ns: str, iface: str, cidr: str) -> None:
    ns_exec(ns, ["ip", "addr", "add", cidr, "dev", iface])


def replace_default_route(ns: str, via: str) -> None:
    ns_exec(ns, ["ip", "route", "replace", "default", "via", via])


def setup_common_topology() -> None:
    do_down(quiet=True)
    setup_namespaces()
    setup_links()


def afp_up(*, quiet: bool = False) -> None:
    setup_common_topology()

    add_address(CLIENT_NS, CLIENT_IF, AFP_CLIENT_IP)
    add_address(SERVER_NS, SERVER_IF, AFP_SERVER_IP)

    bring_up_interface(CLIENT_NS, CLIENT_IF)
    bring_up_interface(SERVER_NS, SERVER_IF)
    bring_up_interface(DUT_NS, DUT_CLIENT_IF)
    bring_up_interface(DUT_NS, DUT_SERVER_IF)

    if not quiet:
        print("AF_PACKET lab is up.")
        print(f"  client namespace: {CLIENT_NS}")
        print(f"  server namespace: {SERVER_NS}")
        print(f"  dut namespace:    {DUT_NS}")
        print()
        print("Interfaces:")
        print(f"  {CLIENT_NS}: {CLIENT_IF} ({AFP_CLIENT_IP})")
        print(f"  {DUT_NS}:    {DUT_CLIENT_IF}")
        print(f"  {DUT_NS}:    {DUT_SERVER_IF}")
        print(f"  {SERVER_NS}: {SERVER_IF} ({AFP_SERVER_IP})")
        print()
        print("Traffic path for AF_PACKET inline testing:")
        print(
            f"  {CLIENT_NS}:{CLIENT_IF} -> {DUT_NS}:{DUT_CLIENT_IF} ... Suricata ... "
            f"{DUT_NS}:{DUT_SERVER_IF} -> {SERVER_NS}:{SERVER_IF}"
        )
        print()
        print("Notes:")
        print("  - No Linux bridge is created.")
        print(
            "  - Client and server can only communicate once something in the DUT forwards traffic between its two interfaces."
        )


def setup_afp_bridge() -> None:
    ns_exec(DUT_NS, ["ip", "link", "add", "name", DUT_BRIDGE_IF, "type", "bridge"])
    ns_exec(DUT_NS, ["ip", "link", "set", DUT_CLIENT_IF, "master", DUT_BRIDGE_IF])
    ns_exec(DUT_NS, ["ip", "link", "set", DUT_SERVER_IF, "master", DUT_BRIDGE_IF])
    ns_exec(DUT_NS, ["ip", "link", "set", DUT_BRIDGE_IF, "up"])


def afp_bridge_up(*, quiet: bool = False) -> None:
    setup_common_topology()

    add_address(CLIENT_NS, CLIENT_IF, AFP_CLIENT_IP)
    add_address(SERVER_NS, SERVER_IF, AFP_SERVER_IP)

    setup_afp_bridge()

    bring_up_interface(CLIENT_NS, CLIENT_IF)
    bring_up_interface(SERVER_NS, SERVER_IF)
    bring_up_interface(DUT_NS, DUT_CLIENT_IF)
    bring_up_interface(DUT_NS, DUT_SERVER_IF)

    if not quiet:
        print("AF_PACKET bridge lab is up.")
        print(f"  client namespace: {CLIENT_NS}")
        print(f"  server namespace: {SERVER_NS}")
        print(f"  dut namespace:    {DUT_NS}")
        print()
        print("Interfaces:")
        print(f"  {CLIENT_NS}: {CLIENT_IF} ({AFP_CLIENT_IP})")
        print(f"  {DUT_NS}:    {DUT_CLIENT_IF} -> {DUT_BRIDGE_IF}")
        print(f"  {DUT_NS}:    {DUT_SERVER_IF} -> {DUT_BRIDGE_IF}")
        print(f"  {SERVER_NS}: {SERVER_IF} ({AFP_SERVER_IP})")
        print()
        print("Traffic path for AF_PACKET bridge testing:")
        print(
            f"  {CLIENT_NS}:{CLIENT_IF} -> {DUT_NS}:{DUT_CLIENT_IF} -> "
            f"{DUT_BRIDGE_IF} -> {DUT_NS}:{DUT_SERVER_IF} -> {SERVER_NS}:{SERVER_IF}"
        )
        print()
        print("Notes:")
        print(f"  - A Linux bridge ({DUT_BRIDGE_IF}) is created in the DUT namespace.")
        print(
            "  - Client and server can communicate without Suricata forwarding traffic between the DUT interfaces."
        )


def setup_nfq_iptables() -> None:
    ns_exec(DUT_NS, ["iptables", "-F"])
    ns_exec(DUT_NS, ["iptables", "-P", "FORWARD", "DROP"])
    ns_exec(
        DUT_NS,
        [
            "iptables",
            "-A",
            "FORWARD",
            "-i",
            DUT_CLIENT_IF,
            "-o",
            DUT_SERVER_IF,
            "-j",
            "NFQUEUE",
            "--queue-num",
            NFQ_QUEUE_NUM,
        ],
    )
    ns_exec(
        DUT_NS,
        [
            "iptables",
            "-A",
            "FORWARD",
            "-i",
            DUT_CLIENT_IF,
            "-o",
            DUT_SERVER_IF,
            "-j",
            "ACCEPT",
        ],
    )
    ns_exec(
        DUT_NS,
        [
            "iptables",
            "-A",
            "FORWARD",
            "-i",
            DUT_SERVER_IF,
            "-o",
            DUT_CLIENT_IF,
            "-j",
            "NFQUEUE",
            "--queue-num",
            NFQ_QUEUE_NUM,
        ],
    )
    ns_exec(
        DUT_NS,
        [
            "iptables",
            "-A",
            "FORWARD",
            "-i",
            DUT_SERVER_IF,
            "-o",
            DUT_CLIENT_IF,
            "-j",
            "ACCEPT",
        ],
    )


def nfq_up(*, quiet: bool = False) -> None:
    setup_common_topology()

    add_address(CLIENT_NS, CLIENT_IF, NFQ_CLIENT_IP)
    add_address(SERVER_NS, SERVER_IF, NFQ_SERVER_IP)
    add_address(DUT_NS, DUT_CLIENT_IF, NFQ_DUT_CLIENT_IP)
    add_address(DUT_NS, DUT_SERVER_IF, NFQ_DUT_SERVER_IP)

    bring_up_interface(CLIENT_NS, CLIENT_IF)
    bring_up_interface(SERVER_NS, SERVER_IF)
    bring_up_interface(DUT_NS, DUT_CLIENT_IF)
    bring_up_interface(DUT_NS, DUT_SERVER_IF)

    replace_default_route(CLIENT_NS, NFQ_CLIENT_GW)
    replace_default_route(SERVER_NS, NFQ_SERVER_GW)

    ns_exec(DUT_NS, ["sysctl", "-w", "net.ipv4.ip_forward=1"], quiet=True)
    setup_nfq_iptables()

    if not quiet:
        print("NFQ lab is up.")
        print(f"  client namespace: {CLIENT_NS}")
        print(f"  server namespace: {SERVER_NS}")
        print(f"  dut namespace:    {DUT_NS}")
        print()
        print("Interfaces:")
        print(f"  {CLIENT_NS}: {CLIENT_IF} ({NFQ_CLIENT_IP})")
        print(f"  {DUT_NS}:    {DUT_CLIENT_IF} ({NFQ_DUT_CLIENT_IP})")
        print(f"  {DUT_NS}:    {DUT_SERVER_IF} ({NFQ_DUT_SERVER_IP})")
        print(f"  {SERVER_NS}: {SERVER_IF} ({NFQ_SERVER_IP})")
        print()
        print("Routing path for NFQUEUE IPS testing:")
        print(
            f"  {CLIENT_NS}:{CLIENT_IF} -> {DUT_NS}:{DUT_CLIENT_IF} -> routing/NFQUEUE -> "
            f"{DUT_NS}:{DUT_SERVER_IF} -> {SERVER_NS}:{SERVER_IF}"
        )
        print()
        print("Notes:")
        print(f"  - The DUT queues forwarded packets to NFQUEUE {NFQ_QUEUE_NUM}.")
        print(
            "  - Packets require a userspace verdict, e.g. from Suricata, before they will be forwarded."
        )


def do_down(*, quiet: bool = False) -> None:
    for ns in ALL_NAMESPACES:
        kill_ns_processes(ns)

    for link in ROOT_LINKS:
        run_quiet(["ip", "link", "del", link])

    for ns in ALL_NAMESPACES:
        run_quiet(["ip", "netns", "del", ns])

    if not quiet:
        print("Lab torn down.")


def show_common_status() -> None:
    print("Namespaces:")
    show(["ip", "netns", "list"])

    print(f"\n{CLIENT_NS} namespace:")
    ns_show(CLIENT_NS, ["ip", "addr"])
    ns_show(CLIENT_NS, ["ip", "route"])

    print(f"\n{SERVER_NS} namespace:")
    ns_show(SERVER_NS, ["ip", "addr"])
    ns_show(SERVER_NS, ["ip", "route"])

    print(f"\n{DUT_NS} namespace:")
    ns_show(DUT_NS, ["ip", "addr"])
    ns_show(DUT_NS, ["ip", "route"])


def afp_status() -> None:
    print("Mode: afp")
    show_common_status()


def afp_bridge_status() -> None:
    print("Mode: ids")
    show_common_status()
    print(f"\n{DUT_NS} bridge:")
    ns_show(DUT_NS, ["ip", "link", "show", DUT_BRIDGE_IF])
    print(f"\n{DUT_NS} bridge ports:")
    ns_show(DUT_NS, ["ip", "link", "show", "master", DUT_BRIDGE_IF])


def nfq_status() -> None:
    print("Mode: nfq")
    show_common_status()
    print(f"\n{DUT_NS} forwarding:")
    ns_show(DUT_NS, ["sysctl", "net.ipv4.ip_forward"])
    print(f"\n{DUT_NS} iptables FORWARD rules:")
    ns_show(DUT_NS, ["iptables", "-S", "FORWARD"])


def do_shell(target: str) -> None:
    namespaces = {
        "client": CLIENT_NS,
        "server": SERVER_NS,
        "dut": DUT_NS,
    }
    os.execvp("ip", ["ip", "netns", "exec", namespaces[target], "bash"])


UP_FUNCS = {
    "nfq": nfq_up,
    "afp": afp_up,
    "ids": afp_bridge_up,
}

STATUS_FUNCS = {
    "afp": afp_status,
    "ids": afp_bridge_status,
    "nfq": nfq_status,
}


SURICATA_READY_MARKER = "Engine started"


def render_test_include(test_dir: str, output_dir: str) -> str | None:
    """Render test include.yaml into the output directory, if present."""
    src = os.path.join(test_dir, "include.yaml")
    if not os.path.isfile(src):
        return None

    with open(src, encoding="utf-8") as f:
        content = f.read()

    content = content.replace("${TESTDIR}", os.path.realpath(test_dir))
    content = content.replace("${OUTDIR}", os.path.realpath(output_dir))

    dst = os.path.join(output_dir, "include.yaml")
    with open(dst, "w", encoding="utf-8") as f:
        f.write(content)
    return dst


def get_include_args(
    mode: str, script_dir: str, test_include: str | None = None
) -> list[str]:
    """Return Suricata --include args for the selected mode and test."""
    args = []
    if mode == "afp":
        args += ["--include", os.path.join(script_dir, "etc", "af-packet.yaml")]
    if test_include:
        args += ["--include", os.path.realpath(test_include)]
    return args


def build_test_env(test_dir: str, output_dir: str) -> dict[str, str]:
    """Return the standard environment exposed to test scripts and checks."""
    env = os.environ.copy()
    env["SRCDIR"] = os.getcwd()
    env["TZ"] = "UTC"
    env["TESTDIR"] = os.path.realpath(test_dir)
    env["TEST_DIR"] = env["TESTDIR"]
    env["OUTDIR"] = os.path.realpath(output_dir)
    env["OUTPUT_DIR"] = env["OUTDIR"]
    return env


def get_test_args(
    config: dict, test_dir: str | None = None, output_dir: str | None = None
) -> list[str]:
    """Return extra Suricata CLI args from test.yaml."""
    raw_args = config.get("args", [])
    if raw_args is None:
        return []
    if not isinstance(raw_args, list):
        raise ValueError('test.yaml "args" must be an array')

    substitutions = {"SRCDIR": os.getcwd()}
    if test_dir:
        substitutions["TESTDIR"] = os.path.realpath(test_dir)
        substitutions["TEST_DIR"] = substitutions["TESTDIR"]
    if output_dir:
        substitutions["OUTDIR"] = os.path.realpath(output_dir)
        substitutions["OUTPUT_DIR"] = substitutions["OUTDIR"]

    args: list[str] = []
    for arg in raw_args:
        if not isinstance(arg, str):
            raise ValueError('test.yaml "args" entries must be strings')
        rendered = string.Template(arg).safe_substitute(substitutions)
        args.extend(shlex.split(rendered))
    return args


def start_suricata(
    mode: str,
    script_dir: str,
    test_dir: str,
    output_dir: str,
    config: dict,
    test_include: str | None = None,
) -> subprocess.Popen[str]:
    """Start Suricata in the DUT namespace and return the Popen handle."""
    cwd = os.getcwd()
    suricata_bin = os.path.join(cwd, "src", "suricata")
    suricata_yaml = os.path.join(cwd, "suricata.yaml")

    cmd = [
        "ip",
        "netns",
        "exec",
        DUT_NS,
        suricata_bin,
        "-c",
        suricata_yaml,
        *get_include_args(mode, script_dir, test_include),
        "-l",
        output_dir,
        "--set",
        f"unix-command.filename={os.path.join(output_dir, 'suricata.socket')}",
        "--set",
        f"classification-file={os.path.join(cwd, 'etc', 'classification.config')}",
        "--set",
        "reference-config-file=./etc/reference.config",
        "--set",
        "threshold-file=./threshold.config",
    ]

    if mode == "ids":
        cmd += ["-i", DUT_BRIDGE_IF]
    elif mode == "afp":
        cmd += ["--af-packet"]
    elif mode == "nfq":
        cmd += ["-q", NFQ_QUEUE_NUM]
    else:
        raise ValueError(f"start_suricata: unsupported mode '{mode}'")

    cmd += get_test_args(config, test_dir, output_dir)

    if verbose:
        print(f"===> Suricata command: {shlex.join(cmd)}")

    return subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )


def tee_stream(pipe, log_file, label: str) -> None:
    """Read from pipe, write every line to log_file, and print if verbose.

    During shutdown, another thread may close either the pipe or the log file.
    Treat that as normal teardown instead of raising noisy thread exceptions.
    """
    try:
        for line in pipe:
            try:
                log_file.write(line)
                log_file.flush()
            except ValueError:
                return
            if verbose:
                print(f"===> {label}: {line}", end="")
    except ValueError:
        return


def wait_for_suricata(
    proc: subprocess.Popen[str], stdout_log, timeout: float = 60
) -> bool:
    """Wait until Suricata logs that the engine has started. Returns True on success."""
    deadline = time.monotonic() + timeout
    assert proc.stdout is not None
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                print(
                    "===> ERROR: Suricata exited before becoming ready", file=sys.stderr
                )
                return False
            continue
        stdout_log.write(line)
        stdout_log.flush()
        if verbose:
            print(f"===> suricata stdout: {line}", end="")
        if SURICATA_READY_MARKER in line:
            return True
    print("===> ERROR: timed out waiting for Suricata to start", file=sys.stderr)
    return False


def stop_suricata(proc: subprocess.Popen[str], timeout: float = 30) -> int:
    """Send SIGTERM to Suricata and wait for it to exit."""
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(
            "===> WARNING: Suricata did not exit in time, sending SIGKILL",
            file=sys.stderr,
        )
        proc.kill()
        proc.wait()
    return proc.returncode


def write_script(script: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/bash\nset -e\n")
        f.write(script)
        f.flush()
        script_path = f.name
    os.chmod(script_path, 0o755)
    return script_path


def terminate_process_group(pgid: int, timeout: float = 10) -> None:
    """Terminate a process group and wait briefly for it to disappear."""
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)

    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return

    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)


def run_script_logged(
    script: str, cwd: str, stdout_path: str, stderr_path: str, label: str = "script"
) -> int:
    """Run a script, logging stdout/stderr to files and teeing to terminal in real time."""
    script_path = write_script(script)
    try:
        with open(stdout_path, "w") as out_f, open(stderr_path, "w") as err_f:
            proc = subprocess.Popen(
                ["bash", script_path],
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            stdout_thread = threading.Thread(
                target=tee_stream,
                args=(proc.stdout, out_f, f"{label} stdout"),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=tee_stream,
                args=(proc.stderr, err_f, f"{label} stderr"),
                daemon=True,
            )
            stdout_thread.start()
            stderr_thread.start()
            result = proc.wait()
            terminate_process_group(proc.pid)

            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    try:
                        pipe.close()
                    except Exception:
                        pass

            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
        return result
    finally:
        os.unlink(script_path)


@dataclass
class ServerScript:
    """Manages a background server script with log capture and cleanup."""

    proc: subprocess.Popen[str]
    script_path: str
    stdout_log: IO[str]
    stderr_log: IO[str]
    stdout_thread: threading.Thread
    stderr_thread: threading.Thread

    def wait_for_start(self, grace_period: float = 0.5) -> bool:
        """Return True if the script stays alive for a brief startup window."""
        deadline = time.monotonic() + grace_period
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                return False
            time.sleep(0.1)
        return self.proc.poll() is None

    def stop(self, timeout: float = 10) -> int:
        """Stop the script, join threads, close logs, and clean up the temp file."""
        terminate_process_group(self.proc.pid, timeout=timeout)
        self.proc.wait()

        # Ensure the tee threads see EOF/shutdown before we close their log files.
        for pipe in (self.proc.stdout, self.proc.stderr):
            if pipe is not None:
                try:
                    pipe.close()
                except Exception:
                    pass

        self.stdout_thread.join(timeout=5)
        self.stderr_thread.join(timeout=5)
        self.stdout_log.close()
        self.stderr_log.close()

        try:
            os.unlink(self.script_path)
        except FileNotFoundError:
            pass

        return self.proc.returncode if self.proc.returncode is not None else 0


def start_background_script(
    script: str,
    cwd: str,
    stdout_path: str,
    stderr_path: str,
    label: str = "script",
) -> ServerScript:
    """Start a background server script, logging stdout/stderr to files. Print if verbose."""
    script_path = write_script(script)
    try:
        proc = subprocess.Popen(
            ["bash", script_path],
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
    except Exception:
        os.unlink(script_path)
        raise

    stdout_log = open(stdout_path, "w")
    stderr_log = open(stderr_path, "w")
    stdout_thread = threading.Thread(
        target=tee_stream,
        args=(proc.stdout, stdout_log, f"{label} stdout"),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=tee_stream,
        args=(proc.stderr, stderr_log, f"{label} stderr"),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    return ServerScript(
        proc=proc,
        script_path=script_path,
        stdout_log=stdout_log,
        stderr_log=stderr_log,
        stdout_thread=stdout_thread,
        stderr_thread=stderr_thread,
    )


class UnsatisfiedRequirementError(Exception):
    pass


SuricataVersion = namedtuple("SuricataVersion", ["major", "minor", "patch"])


def parse_suricata_version(
    buf: object, expr: str | None = None
) -> SuricataVersion | None:
    m = re.search(
        r"(?:Suricata version |^)(\d+)\.?((?:\d+))?\.?((?:\d+))?.*", str(buf).strip()
    )
    default_v = 0
    if expr == "equal":
        default_v = None
    if not m:
        return None

    major = int(m.group(1)) if m.group(1) else default_v
    minor = int(m.group(2)) if m.group(2) else default_v
    patch = int(m.group(3)) if m.group(3) else default_v
    return SuricataVersion(major=major, minor=minor, patch=patch)


class Version:
    """Class to compare Suricata versions."""

    def is_equal(self, a: SuricataVersion, b: SuricataVersion) -> bool:
        if a.major != b.major:
            return False
        if a.minor is not None and b.minor is not None and a.minor != b.minor:
            return False
        if a.patch is not None and b.patch is not None and a.patch != b.patch:
            return False
        return True

    def is_gte(self, v1: SuricataVersion, v2: SuricataVersion) -> bool:
        if v1.major < v2.major:
            return False
        if v1.major > v2.major:
            return True
        if v1.minor < v2.minor:
            return False
        if v1.minor > v2.minor:
            return True
        if v1.patch < v2.patch:
            return False
        return True

    def is_gt(self, v1: SuricataVersion, v2: SuricataVersion) -> bool:
        if v1.major < v2.major:
            return False
        if v1.major > v2.major:
            return True
        if v1.minor < v2.minor:
            return False
        if v1.minor > v2.minor:
            return True
        if v1.patch < v2.patch:
            return False
        if v1.patch == v2.patch:
            return False
        return True

    def is_lt(self, v1: SuricataVersion, v2: SuricataVersion) -> bool:
        if v1.major > v2.major:
            return False
        if v1.major < v2.major:
            return True
        if v1.minor < v2.minor:
            return True
        if v1.patch < v2.patch:
            return True
        return False


class SuricataConfig:
    def __init__(self, suricata_bin: str, version: SuricataVersion) -> None:
        self.suricata_bin = suricata_bin
        self.version = version
        self.features = set()
        self.config = {}
        self.load_build_info()

    def load_build_info(self) -> None:
        output = subprocess.check_output([self.suricata_bin, "--build-info"])
        start_support = False
        for line in output.splitlines():
            decoded = line.decode()
            if decoded.startswith("Features:"):
                self.features = set(decoded.split()[1:])
            if "Suricata Configuration" in decoded:
                start_support = True
            if start_support and "support:" in decoded:
                fkey, val = decoded.split(" support:")
                fkey = fkey.strip()
                val = val.strip()
                if val.startswith("yes"):
                    self.features.add(fkey)

    def load_config(
        self, config_filename: str, extra_args: list[str] | None = None
    ) -> None:
        cmd = [self.suricata_bin, "-c", config_filename]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append("--dump-config")
        output = subprocess.check_output(cmd)
        self.config = {}
        for line in output.decode("utf-8").split("\n"):
            parts = [p.strip() for p in line.split("=", 1)]
            if parts and parts[0]:
                self.config[parts[0]] = parts[1] if len(parts) > 1 else ""

    def has_feature(self, feature: str) -> bool:
        return feature in self.features


def get_suricata_config(
    mode: str,
    script_dir: str,
    config: dict,
    test_dir: str,
    output_dir: str,
    test_include: str | None = None,
) -> SuricataConfig:
    extra_args = [
        *get_include_args(mode, script_dir, test_include),
        *get_test_args(config, test_dir, output_dir),
    ]
    cache_key = (
        mode,
        os.path.realpath(test_include) if test_include else None,
        tuple(extra_args),
    )
    if cache_key in suricata_config_cache:
        return suricata_config_cache[cache_key]

    cwd = os.getcwd()
    suricata_bin = os.path.join(cwd, "src", "suricata")
    suricata_yaml = os.path.join(cwd, "suricata.yaml")
    version = parse_suricata_version(subprocess.check_output([suricata_bin, "-V"]))
    if version is None:
        raise ValueError("failed to determine Suricata version")

    suricata_config = SuricataConfig(suricata_bin, version)
    suricata_config.load_config(suricata_yaml, extra_args)
    suricata_config_cache[cache_key] = suricata_config
    return suricata_config


def is_version_compatible(
    version: str, suri_version: SuricataVersion, expr: str
) -> bool:
    config_version = parse_suricata_version(version, expr)
    if config_version is None:
        return False
    version_obj = Version()
    func = getattr(version_obj, f"is_{expr}")
    return func(suri_version, config_version)


def check_requires(
    requires: dict, suricata_config: SuricataConfig, test_dir: str | None = None
) -> None:
    suri_version = suricata_config.version
    for key in requires:
        if key == "min-version":
            min_version = requires["min-version"]
            if not is_version_compatible(min_version, suri_version, "gte"):
                raise UnsatisfiedRequirementError(
                    f"requires at least version {min_version}"
                )
        elif key == "lt-version":
            lt_version = requires["lt-version"]
            if not is_version_compatible(lt_version, suri_version, "lt"):
                raise UnsatisfiedRequirementError(f"for version less than {lt_version}")
        elif key == "gt-version":
            gt_version = requires["gt-version"]
            if not is_version_compatible(gt_version, suri_version, "gt"):
                raise UnsatisfiedRequirementError(
                    f"for version greater than {gt_version}"
                )
        elif key == "version":
            req_version = requires["version"]
            if not is_version_compatible(req_version, suri_version, "equal"):
                raise UnsatisfiedRequirementError(f"only for version {req_version}")
        elif key == "features":
            for feature in requires["features"]:
                if not suricata_config.has_feature(feature):
                    raise UnsatisfiedRequirementError(f"requires feature {feature}")
        elif key == "env":
            for env in requires["env"]:
                if env not in os.environ:
                    raise UnsatisfiedRequirementError(f"requires env var {env}")
        elif key == "files":
            for filename in requires["files"]:
                if test_dir and not os.path.isabs(filename):
                    filename = os.path.join(test_dir, filename)
                if not os.path.exists(filename):
                    raise UnsatisfiedRequirementError(f"requires file {filename}")
        elif key == "script":
            for script in requires["script"]:
                try:
                    subprocess.check_call(f"{script}", shell=True)
                except Exception as err:
                    raise UnsatisfiedRequirementError(
                        f"requires script returned false: {err}"
                    ) from err
        elif key == "pcap":
            pass
        elif key == "lambda":
            if not eval(requires["lambda"]):
                raise UnsatisfiedRequirementError(requires["lambda"])
        elif key == "os":
            cur_platform = platform.system().lower()
            if not cur_platform.startswith(requires["os"].lower()):
                raise UnsatisfiedRequirementError(requires["os"])
        elif key == "arch":
            cur_arch = platform.machine().lower()
            if not cur_arch.startswith(requires["arch"].lower()):
                raise UnsatisfiedRequirementError(requires["arch"])
        else:
            raise ValueError(f"unknown requires type: {key}")


def find_value(name: str, obj: object) -> object | None:
    """Find the value in an object for a field specified by name.

    Example names:
      event_type
      alert.signature_id
      smtp.rcpt_to[0]
    """
    parts = name.split(".")
    for part in parts:
        if part == "__len":
            try:
                return len(obj)
            except Exception:
                return -1

        if part in ["__contains", "__find", "__startswith", "__endswith"]:
            break

        index = None
        m = re.match(r"^(.*)\[(\d+)\]$", part)
        if m:
            name = m.group(1)
            index = m.group(2)
        else:
            name = part

        if not isinstance(obj, dict) or name not in obj:
            return None
        obj = obj[name]

        if index is not None:
            try:
                obj = obj[int(index)]
            except Exception:
                return None

    return obj


class StatsCheck:
    """Check values in the last stats event of eve.json."""

    def __init__(self, config: dict, output_dir: str) -> None:
        self.config = config
        self.output_dir = output_dir

    def run(self) -> list[str]:
        """Return a list of failure messages (empty on success)."""
        eve_json_path = os.path.join(self.output_dir, "eve.json")
        if not os.path.exists(eve_json_path):
            return [f"eve.json not found: {eve_json_path}"]

        stats = None
        with open(eve_json_path) as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "stats":
                        stats = event["stats"]
                except json.JSONDecodeError:
                    pass

        if stats is None:
            return ["no stats event found in eve.json"]

        failures = []
        for key, expected in self.config.items():
            val = find_value(key, stats)
            if val != expected:
                failures.append(f"stats.{key}: expected {expected}; got {val}")
        return failures


class ShellCheck:
    """Run a shell command in the test output directory."""

    def __init__(
        self,
        config: dict,
        env: dict[str, str],
        output_dir: str,
        suricata_config: SuricataConfig,
        test_dir: str | None = None,
    ) -> None:
        for key in config:
            if key not in ["requires", "args", "expect"]:
                raise ValueError(f"Unexpected key in shell check: {key}")
        if "args" not in config:
            raise ValueError("shell check missing args")
        self.config = config
        self.env = env
        self.output_dir = output_dir
        self.suricata_config = suricata_config
        self.test_dir = test_dir

    def run(self) -> tuple[list[str], list[str]]:
        warnings = []
        requires = self.config.get("requires", {})
        try:
            check_requires(requires, self.suricata_config, self.test_dir)
        except UnsatisfiedRequirementError as err:
            warnings.append(f"SKIP: shell check skipped: {err}")
            return [], warnings

        result = subprocess.run(
            ["bash", "-c", self.config["args"]],
            cwd=self.output_dir,
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            details = []
            if result.stdout.strip():
                details.append(f"stdout={result.stdout.strip()!r}")
            if result.stderr.strip():
                details.append(f"stderr={result.stderr.strip()!r}")
            suffix = f" ({', '.join(details)})" if details else ""
            return [
                f"shell command failed with exit code {result.returncode}: {self.config['args']!r}{suffix}"
            ], warnings

        if "expect" in self.config:
            output = result.stdout.strip()
            if str(self.config["expect"]) != output:
                return [
                    f"shell check expected {self.config['expect']!r}; got {output!r}"
                ], warnings

        return [], warnings


class FilterCheck:
    """Filter JSON lines output and count matching events."""

    def __init__(
        self,
        config: dict,
        output_dir: str,
        suricata_config: SuricataConfig,
        test_dir: str | None = None,
    ) -> None:
        for key in config:
            if key not in ["count", "match", "filename", "requires", "comment"]:
                raise ValueError(f"Unexpected key in filter check: {key}")
        if "count" not in config:
            raise ValueError("filter check missing count")
        if "match" not in config:
            raise ValueError("filter check missing match")
        self.config = config
        self.output_dir = output_dir
        self.suricata_config = suricata_config
        self.test_dir = test_dir

    def run(self) -> tuple[list[str], list[str]]:
        warnings = []
        requires = self.config.get("requires", {})
        try:
            check_requires(requires, self.suricata_config, self.test_dir)
        except UnsatisfiedRequirementError as err:
            warnings.append(f"SKIP: filter check skipped: {err}")
            return [], warnings

        if "filename" in self.config:
            json_filename = self.config["filename"]
            if not os.path.isabs(json_filename):
                json_filename = os.path.join(self.output_dir, json_filename)
        else:
            json_filename = os.path.join(self.output_dir, "eve.json")

        if not os.path.exists(json_filename):
            return [f"{json_filename} does not exist"], warnings

        count = 0
        try:
            with open(json_filename, "r", encoding="utf-8") as fileobj:
                for line in fileobj:
                    event = json.loads(line)
                    if self.match(event):
                        count += 1
        except Exception as err:
            return [f"filter check failed for {json_filename}: {err}"], warnings

        if count == self.config["count"]:
            return [], warnings
        if "comment" in self.config:
            return [
                f"{self.config['comment']}: expected {self.config['count']}, got {count}"
            ], warnings
        return [
            f"expected {self.config['count']} matches; got {count} for filter {self.config}"
        ], warnings

    def match(self, event: dict) -> bool:
        for key, expected in self.config["match"].items():
            if key == "has-key":
                if find_value(expected, event) is None:
                    return False
            elif key == "not-has-key":
                if find_value(expected, event) is not None:
                    return False
            else:
                val = find_value(key, event)
                if key.endswith("__find"):
                    if val is None or str(val).find(str(expected)) < 0:
                        return False
                elif key.endswith("__contains"):
                    if val is None or expected not in val:
                        return False
                elif key.endswith("__startswith"):
                    if val is None or not str(val).startswith(str(expected)):
                        return False
                elif key.endswith("__endswith"):
                    if val is None or not str(val).endswith(str(expected)):
                        return False
                elif val != expected:
                    return False
        return True


def run_checks(
    config: dict, output_dir: str, mode: str, script_dir: str, test_dir: str
) -> tuple[list[str], list[str]]:
    """Run post-teardown checks.

    Returns (failures, warnings).
    """
    failures = []
    warnings = []
    supported_checks = {"stats", "filter", "shell"}
    suricata_config = None
    test_include = os.path.join(output_dir, "include.yaml")
    if not os.path.isfile(test_include):
        test_include = None

    for i, check in enumerate(config.get("checks", []), start=1):
        if "stats" in check:
            failures.extend(StatsCheck(check["stats"], output_dir).run())
        if "filter" in check or "shell" in check:
            try:
                if suricata_config is None:
                    suricata_config = get_suricata_config(
                        mode, script_dir, config, test_dir, output_dir, test_include
                    )
                if "filter" in check:
                    check_failures, check_warnings = FilterCheck(
                        check["filter"], output_dir, suricata_config, test_dir
                    ).run()
                    failures.extend(check_failures)
                    warnings.extend(check_warnings)
                if "shell" in check:
                    check_failures, check_warnings = ShellCheck(
                        check["shell"],
                        build_test_env(test_dir, output_dir),
                        output_dir,
                        suricata_config,
                        test_dir,
                    ).run()
                    failures.extend(check_failures)
                    warnings.extend(check_warnings)
            except Exception as err:
                check_type = "filter" if "filter" in check else "shell"
                failures.append(f"{check_type} check #{i} failed: {err}")
        for key in check:
            if key not in supported_checks:
                warnings.append(
                    f"WARNING: unsupported check type '{key}' in check #{i}"
                )
    return failures, warnings


def add_script_log_paths(failures: list[str], output_dir: str, name: str) -> None:
    """Append the stdout/stderr log paths for a script to the failure list."""
    failures.append(f"{name} stdout: {os.path.join(output_dir, f'{name}.stdout')}")
    failures.append(f"{name} stderr: {os.path.join(output_dir, f'{name}.stderr')}")


def log_test_step(mode: str, test_name: str, message: str) -> None:
    print(f"===> [{mode}/{test_name}] {message}", flush=True)


def run_test(
    test_name: str, mode: str, config: dict, script_dir: str, test_dir: str
) -> list[str]:
    """Run a single test in the given mode. Returns failure messages."""
    failures = []
    client_script = config.get("client")
    if not client_script:
        return ["no client script defined"]

    before_script = config.get("before")
    server_script = config.get("server")

    output_dir = os.path.join(test_dir, "output", mode)
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    test_env = build_test_env(test_dir, output_dir)
    managed_env_keys = ["SRCDIR", "TZ", "TESTDIR", "TEST_DIR", "OUTDIR", "OUTPUT_DIR"]
    prev_test_env = {key: os.environ.get(key) for key in managed_env_keys}
    for key in managed_env_keys:
        os.environ[key] = test_env[key]
    test_include = render_test_include(test_dir, output_dir)

    log_test_step(mode, test_name, f"Setting up {mode} environment")
    UP_FUNCS[mode](quiet=True)

    stdout_log = None
    stderr_log = None
    suricata = None
    stderr_thread = None
    stdout_thread = None
    server: ServerScript | None = None
    client_rc = -1
    server_rc = 0
    try:
        if before_script:
            log_test_step(mode, test_name, "Running before script")
            before_rc = run_script_logged(
                before_script,
                test_dir,
                os.path.join(output_dir, "before.stdout"),
                os.path.join(output_dir, "before.stderr"),
                label="before",
            )
            if before_rc != 0:
                failures.append(f"before script exited with code {before_rc}")
                add_script_log_paths(failures, output_dir, "before")
                return failures

        log_test_step(mode, test_name, "Starting Suricata")

        stdout_log = open(os.path.join(output_dir, "stdout"), "w")
        stderr_log = open(os.path.join(output_dir, "stderr"), "w")
        try:
            suricata = start_suricata(
                mode, script_dir, test_dir, output_dir, config, test_include
            )
        except ValueError as err:
            failures.append(str(err))
            return failures

        stderr_thread = threading.Thread(
            target=tee_stream,
            args=(suricata.stderr, stderr_log, "suricata stderr"),
            daemon=True,
        )
        stderr_thread.start()

        if not wait_for_suricata(suricata, stdout_log):
            failures.append("Suricata did not become ready")
            failures.append(f"suricata stdout: {os.path.join(output_dir, 'stdout')}")
            failures.append(f"suricata stderr: {os.path.join(output_dir, 'stderr')}")
            return failures

        stdout_thread = threading.Thread(
            target=tee_stream,
            args=(suricata.stdout, stdout_log, "suricata stdout"),
            daemon=True,
        )
        stdout_thread.start()

        if server_script:
            log_test_step(mode, test_name, "Starting Server")
            server = start_background_script(
                server_script,
                test_dir,
                os.path.join(output_dir, "server.stdout"),
                os.path.join(output_dir, "server.stderr"),
                label="server",
            )
            if not server.wait_for_start():
                server_rc = (
                    server.proc.returncode if server.proc.returncode is not None else 1
                )
                failures.append(
                    f"server script exited during startup with code {server_rc}"
                )
                add_script_log_paths(failures, output_dir, "server")
                return failures

        log_test_step(mode, test_name, "Running Client")
        client_rc = run_script_logged(
            client_script,
            test_dir,
            os.path.join(output_dir, "client.stdout"),
            os.path.join(output_dir, "client.stderr"),
            label="client",
        )
        if client_rc != 0:
            failures.append(f"client script exited with code {client_rc}")
            add_script_log_paths(failures, output_dir, "client")

        if server and server.proc.poll() is not None:
            server_rc = server.proc.returncode
            if server_rc != 0:
                failures.append(f"server script exited with code {server_rc}")
                add_script_log_paths(failures, output_dir, "server")
    finally:
        if server:
            log_test_step(mode, test_name, "Stopping Server")
            server.stop()
        if suricata:
            log_test_step(mode, test_name, "Stopping Suricata")
            stop_suricata(suricata)
        if stdout_thread:
            stdout_thread.join(timeout=5)
        if stderr_thread:
            stderr_thread.join(timeout=5)
        if stdout_log:
            stdout_log.close()
        if stderr_log:
            stderr_log.close()
        do_down(quiet=True)
        for key, value in prev_test_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    return failures


def do_run(
    *,
    only_mode: str | None = None,
    substring: str | None = None,
    tags: list[str] | None = None,
) -> bool:
    """Run tests. Returns True if all tests passed."""
    all_passed = True
    selected_tags = {tag.strip().lower() for tag in (tags or []) if tag.strip()}
    script_dir = os.path.dirname(os.path.realpath(__file__))
    tests_dir = os.path.join(script_dir, "tests")
    for root, dirs, files in os.walk(tests_dir):
        dirs.sort()
        if "test.yaml" not in files:
            continue

        test_name = os.path.basename(root)
        if substring and substring not in test_name:
            continue
        if selected_tags:
            try:
                test_tags = get_test_tags(root)
            except ValueError as err:
                print(f"ERROR: {err}", file=sys.stderr)
                all_passed = False
                continue
            if not selected_tags.issubset(test_tags):
                continue

        test_yaml = os.path.join(root, "test.yaml")
        with open(test_yaml) as f:
            config = yaml.safe_load(f)

        modes = config.get("mode", [])
        if isinstance(modes, str):
            modes = [modes]

        for mode in modes:
            if only_mode and mode != only_mode:
                continue
            if mode not in UP_FUNCS:
                print(f"ERROR: unknown mode '{mode}' in {test_yaml}", file=sys.stderr)
                all_passed = False
                continue

            failures = run_test(test_name, mode, config, script_dir, root)
            warnings = []
            if not failures:
                output_dir = os.path.join(root, "output", mode)
                failures, warnings = run_checks(
                    config, output_dir, mode, script_dir, root
                )
            ok = not failures
            log_test_step(mode, test_name, "OK" if ok else "FAIL")
            if not ok:
                all_passed = False
            for msg in warnings:
                print(f"  {msg}")
            for msg in failures:
                print(f"  {msg}")
    return all_passed


def main() -> None:
    global verbose

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(line_buffering=True)

    parser = build_parser()
    args = parser.parse_args()
    verbose = args.verbose
    configure_script_env()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "run":
        need_root()
        for cmd in ["ip", "ethtool", "sysctl", "kill", "iptables"]:
            need_cmd(cmd)
        if not do_run(only_mode=args.mode, substring=args.substring, tags=args.tag):
            sys.exit(1)
        return

    mode = args.command
    action = args.action

    if action is None:
        parser.parse_args([mode, "--help"])
        sys.exit(1)

    need_root()

    required_cmds = ["ip", "ethtool", "sysctl", "kill"]
    if mode == "nfq":
        required_cmds.append("iptables")
    for cmd in required_cmds:
        need_cmd(cmd)

    if action == "up":
        UP_FUNCS[mode]()
    elif action == "down":
        do_down()
    elif action == "status":
        STATUS_FUNCS[mode]()
    elif action == "shell":
        do_shell(args.target)


if __name__ == "__main__":
    main()
