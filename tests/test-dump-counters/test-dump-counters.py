#!/usr/bin/env python3
import argparse
import json
import logging
import os
import os.path
import signal
import sys
import time

import suricatasc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pidfile")
    parser.add_argument("--suricata-socket")
    parser.add_argument("--poll-interval", type=float, default=0.1)
    parser.add_argument("--timeout", type=float, default=5)
    parser.add_argument("--verbose", default=False, action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    poll_interval = args.poll_interval
    end_time = time.time() + args.timeout
    suricata_pid = None
    exit_code = 1

    while time.time() < end_time:
        if not os.path.exists(args.pidfile):
            time.sleep(poll_interval)

        if not os.path.exists(args.suricata_socket):
            time.sleep(poll_interval)

        logging.info("pidfile and socket appeared")
        with open(args.pidfile, "r") as fp:
            suricata_pid = int(fp.read())
        exit_code = 2
        break

    while time.time() < end_time:
        sc = suricatasc.SuricataSC(args.suricata_socket, verbose=args.verbose)
        try:
            sc.connect()
        except suricatasc.SuricataException as e:
            logging.info("Failed to connect: %s", e)
            time.sleep(poll_interval)
            continue

        exit_code = 3
        result = sc.send_command("dump-counters")
        if result["return"] != "OK":
            logging.info("Non-OK result: %s", result)
            time.sleep(poll_interval)
            continue

        print(json.dumps(result))
        exit_code = 0
        break

    logging.info("Stopping Suricata")
    os.kill(suricata_pid, signal.SIGTERM)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
