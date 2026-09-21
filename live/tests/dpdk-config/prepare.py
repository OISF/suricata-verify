#!/usr/bin/env python3
"""Prepare a DPDK configuration using CPUs and syntax available on this host."""

import os
from pathlib import Path
import re
import subprocess
import sys

import yaml


kind, threads = sys.argv[1], int(sys.argv[2])
config = yaml.safe_load((Path(__file__).parent / f"{kind}.yaml").read_text())
cpus = sorted(os.sched_getaffinity(0))
if len(cpus) < threads + 1:
    raise SystemExit("need one management CPU and one CPU per worker")
config["threading"]["cpu-affinity"] = [
    {"management-cpu-set": {"cpu": [cpus[0]]}},
    {"worker-cpu-set": {"cpu": cpus[1 : threads + 1], "mode": "exclusive"}},
]

eal = config["dpdk"]["eal-params"]
devices = eal["vdev"] if isinstance(eal["vdev"], list) else [eal["vdev"]]
if kind == "bond":
    version = subprocess.check_output(
        ["pkg-config", "--modversion", "libdpdk"], text=True
    ).strip()
    match = re.match(r"(\d+)\.(\d+)", version)
    if not match:
        raise SystemExit(f"cannot determine DPDK version: {version!r}")
    if tuple(map(int, match.groups())) < (23, 11):
        devices = [device.replace("member=", "slave=") for device in devices]
eal["vdev"] = [
    f"{device},qpairs={threads}" if device.startswith("net_af_packet") else device
    for device in devices
]

output = Path(os.environ["OUTDIR"]) / "dpdk.yaml"
output.write_text("%YAML 1.1\n---\n" + yaml.safe_dump(config, sort_keys=False))
