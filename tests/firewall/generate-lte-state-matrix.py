#!/usr/bin/env python3
# Generates the LTE (<hook) state matrix tests.
#
# For every protocol (http1, tls, http2 stream/global), direction (ts, tc) and
# hookable state, one test per case:
#   single-bare, single-content-match, single-content-nomatch,
#   single-ip-nomatch, multi-same-bare, multi-states,
#   multi-match-content-nomatch, multi-match-ip-nomatch,
#   multi-content-nomatch-next-match, multi-content-nomatch-same-hook-next-match
#
# Rules under test are all in one direction. The opposite direction gets one
# scaffolding accept:hook <last-state rule so its default policy does not drop
# the flow before the tested direction reaches S + 1 (where a phase no match
# becomes final). http2 has two transaction types (the stream and the
# connection-level global tx), so the untested tx type is scaffolded in both
# directions as well.
#
# Content keywords must be registered at exactly the hook state
# (detect-parse.c rejects a mismatch). http1 has no keyword at the trailer and
# complete states, http2 only has http2.header_name (registered at the headers
# state), so those states skip the content dependent cases.
#
# The first state of each direction (progress 0) is skipped: an LTE (<) rule
# there has no prior hooks and is rejected by rule parsing.
#
# Excluded cells: the tls toclient terminal state (server_finished) and the
# toclient server_data no-match case. At flow close only the direction of the
# final ACK gets the EOF evaluation, so rules that need the toclient track to
# reach its completion state are never adjudicated. Follow-up material: the
# final evaluation should be done for both directions.
#
# Usage: python3 generate-lte-state-matrix.py
import os
import yaml

BASE = os.path.dirname(os.path.abspath(__file__))
START = 300

HTTP1_TS = ["request_started", "request_line", "request_headers", "request_body",
            "request_trailer", "request_complete"]
HTTP1_TC = ["response_started", "response_line", "response_headers", "response_body",
            "response_trailer", "response_complete"]
TLS_TS = ["client_started", "client_hello", "client_cert", "client_data", "client_finished"]
TLS_TC = ["server_started", "server_hello", "server_cert", "server_data", "server_finished"]
H2_STREAM_TS = ["request_started", "request_headers", "request_data", "request_closed",
                "request_complete"]
H2_STREAM_TC = ["response_started", "response_headers", "response_data", "response_closed",
                "response_complete"]
H2_GLOBAL_TS = ["request_started", "request_complete"]
H2_GLOBAL_TC = ["response_started", "response_complete"]
SMTP_TS = ["request_started", "request_data", "request_complete"]
SMTP_TC = ["response_started", "response_data", "response_complete"]

# (hook prefix, direction, states, pcap). The hook prefix is the protocol name,
# with the http2 sub-state appended: http2:stream / http2:global.
PROTOCOLS = [
    ("http1", "ts", HTTP1_TS, "../lte-matrix-data/http1.pcap"),
    ("http1", "tc", HTTP1_TC, "../lte-matrix-data/http1.pcap"),
    ("tls", "ts", TLS_TS, "../../tls/tls-client-hello-frag-01/dump_mtu300.pcap"),
    ("tls", "tc", TLS_TC, "../../tls/tls-client-hello-frag-01/dump_mtu300.pcap"),
    ("http2:stream", "ts", H2_STREAM_TS, "../../http2-bugfixes/input.pcap"),
    ("http2:stream", "tc", H2_STREAM_TC, "../../http2-bugfixes/input.pcap"),
    ("http2:global", "ts", H2_GLOBAL_TS, "../../http2-bugfixes/input.pcap"),
    ("http2:global", "tc", H2_GLOBAL_TC, "../../http2-bugfixes/input.pcap"),
    ("smtp", "ts", SMTP_TS, "../lte-matrix-data/smtp.pcap"),
    ("smtp", "tc", SMTP_TC, "../lte-matrix-data/smtp.pcap"),
]

SURICATA_YAML = """%YAML 1.1
---

vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8]"
    EXTERNAL_NET: "!$HOME_NET"

stats:
  enabled: yes
  interval: 8

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - stats
        - flow
        - alert
        - drop:
            alerts: yes
            flows: all

firewall:
  policies:
    # accept the session packets without per-test boilerplate rules
    packet:
      default-policy: ["accept:hook"]
    # drop and alert on the app states no rule covers, for the richer logging
    app:
      tls:
        default-policy: ["drop:flow", "alert"]
      http1:
        default-policy: ["drop:flow", "alert"]
"""

SURICATA_YAML_HTTP2 = SURICATA_YAML.replace(
    """      http1:
        default-policy: ["drop:flow", "alert"]
""",
    """      http1:
        default-policy: ["drop:flow", "alert"]
      http2:
        default-policy: ["drop:flow", "alert"]
""")


SURICATA_YAML_SMTP = SURICATA_YAML.replace(
    """      http1:
        default-policy: ["drop:flow", "alert"]
""",
    """      http1:
        default-policy: ["drop:flow", "alert"]
      smtp:
        default-policy: ["drop:flow", "alert"]
""")


def content(pkey, direction, state):
    """Keyword registered at the state, with matching and non-matching args."""
    if pkey == "tls":
        return {"kw": "tls.version", "match": "1.2", "nomatch": "1.3"}
    if pkey == "smtp":
        if direction == "ts" and state == "request_data":
            return {"kw": "email.from", "match": "alice@example.com",
                    "nomatch": "nope@example.com"}
        return None
    if pkey.startswith("http2"):
        if state.endswith("_headers"):
            return {"kw": "http2.header_name", "match": ":method" if direction == "ts" else ":status",
                    "nomatch": "x-absent"}
        return None
    if state.endswith("_line"):
        if direction == "ts":
            return {"kw": "http.uri", "match": "/index", "nomatch": "/nope"}
        return {"kw": "http.stat_code", "match": "200", "nomatch": "404"}
    if state.endswith("_headers"):
        if direction == "ts":
            return {"kw": "http.host", "match": "www.example.com", "nomatch": "nope.example"}
        return {"kw": "http.header", "match": "X-Marker: yes", "nomatch": "X-Marker: no"}
    if state.endswith("_body"):
        if direction == "ts":
            return {"kw": "http.request_body", "match": "BODY-MARKER",
                    "nomatch": "NEVER-MARKER"}
        return {"kw": "http.response_body", "match": "RESP-BODY", "nomatch": "NEVER-MARKER"}
    return None


def kw_part(c, kind):
    if c["kw"] in ("app-layer-state", "tls.version"):
        return f'{c["kw"]}:{c[kind]};'
    return f'{c["kw"]}; content:"{c[kind]}";'


def addr(pkey, direction, out_of_scope=False):
    if out_of_scope:
        return "198.51.100.0/24 any -> 198.51.100.0/24 any"
    if pkey.startswith("http2"):
        # the http2 fixtures use addresses outside the matrix HOME_NET
        return "any any -> any any"
    if direction == "ts":
        return "$HOME_NET any -> $EXTERNAL_NET any"
    return "$EXTERNAL_NET any -> $HOME_NET any"


def hookstr(pkey, state):
    # the logged hook name is "http" for http1
    return f"{'http' if pkey == 'http1' else pkey}:{state}"


def hook_filter(pkey, state):
    return hookstr(pkey, state)


def rule(pkey, direction, state, opts, sid, out_of_scope=False):
    body = " ".join(x for x in (opts, f"sid:{sid};") if x)
    return (f"accept:flow,alert {pkey}:<{state} {addr(pkey, direction, out_of_scope)} ({body})")


def opposite_last_state(pkey, direction):
    if pkey.startswith("http2"):
        return "response_complete" if direction == "ts" else "request_complete"
    opposite_direction = "tc" if direction == "ts" else "ts"
    return {"http1": HTTP1_TC if opposite_direction == "tc" else HTTP1_TS,
            "tls": TLS_TC if opposite_direction == "tc" else TLS_TS,
            "smtp": SMTP_TC if opposite_direction == "tc" else SMTP_TS}[pkey][-1]


def scaffold(pkey, direction):
    """Rules covering the directions and tx types the tested rule does not."""
    if not pkey.startswith("http2"):
        return [f"accept:hook {pkey}:<{opposite_last_state(pkey, direction)} "
                f"{addr(pkey, 'tc' if direction == 'ts' else 'ts')} (sid:9001;)"]

    other = "http2:global" if pkey == "http2:stream" else "http2:stream"
    lines = [
        # same tx type, opposite direction
        f"accept:hook {pkey}:<{opposite_last_state(pkey, direction)} any any <> any any (sid:9001;)",
        # the other tx type needs both directions covered
        f"accept:hook {other}:<request_complete any any -> any any (sid:9002;)",
        f"accept:hook {other}:<response_complete any any -> any any (sid:9003;)",
    ]
    return lines


def zero_drops(alert_sid, pcap_cnt, hook, no_alert=None):
    alert_match = {"event_type": "alert", "alert.signature_id": alert_sid, "pcap_cnt": pcap_cnt,
                   "alert.action": "allowed"}
    if hook is not None:
        alert_match["firewall.hook"] = hook
    checks = [
        {"filter": {"count": 0, "match": {
            "event_type": "drop", "drop.reason": "firewall default app policy"}}},
        {"filter": {"count": 1, "match": alert_match}},
        {"filter": {"count": 1, "match": {
            "event_type": "flow", "flow.action": "accept", "flow.alerted": True}}},
    ]
    if no_alert is not None:
        checks.append({"filter": {"count": 0, "match": {
            "event_type": "alert", "alert.signature_id": no_alert}}})
    return checks


def one_drop(direction, state, alert_sid, pcap_cnt, hook):
    policy_match = {"event_type": "alert", "alert.signature_id": 2201001, "pcap_cnt": pcap_cnt,
                    "alert.action": "blocked", "firewall.policy": "drop:flow,alert"}
    if hook is not None:
        policy_match["firewall.hook"] = hook
    return [
        {"filter": {"count": 1, "match": {
            "event_type": "drop", "drop.reason": "firewall default app policy",
            "pcap_cnt": pcap_cnt,
            "direction": "to_server" if direction == "ts" else "to_client"}}},
        {"filter": {"count": 1, "match": policy_match}},
        {"filter": {"count": 1, "match": {
            "event_type": "flow", "flow.action": "drop", "flow.alerted": True}}},
        {"filter": {"count": 0, "match": {
            "event_type": "drop", "drop.reason": "firewall rules"}}},
        {"filter": {"count": 0, "match": {
            "event_type": "alert", "alert.signature_id": alert_sid}}},
    ]


def nearest_content_state(pkey, direction, states, i):
    """Closest state other than i that has a keyword, preferring the next one."""
    for d in range(1, len(states)):
        for j in (i + d, i - d):
            if 0 <= j < len(states) and content(pkey, direction, states[j]):
                return states[j]
    return None


def cases_for(pkey, direction, state, states):
    """Return (slug, [rules], [checks], notes) tuples."""
    i = states.index(state)
    next_state = states[i + 1] if i + 1 < len(states) else None
    prev_state = states[i - 1] if i > 0 else None
    c = content(pkey, direction, state)
    when = WHEN[(pkey, direction, state)]
    cases = []

    cases.append(("single-bare",
                  [rule(pkey, direction, state, "", 100)],
                  zero_drops(100, when["bare"], hook_filter(pkey, state)),
                  "Bare < rule: the prior states are auto-accepted and the rule accepts the flow at S."))
    if c and "match" in when:
        cases.append(("single-content-match",
                      [rule(pkey, direction, state, kw_part(c, "match"), 100)],
                      zero_drops(100, when["match"], hook_filter(pkey, state)),
                      f"< rule with a matching {c['kw']} keyword: accepts at S."))
    if c and "content_drop" in when:
        cases.append(("single-content-nomatch",
                      [rule(pkey, direction, state, kw_part(c, "nomatch"), 100)],
                      one_drop(direction, state, 100, when["content_drop"], hook_filter(pkey, state)),
                      f"< rule with a non-matching {c['kw']} keyword: the no match becomes final at S + 1 and the per-state default policy drops the flow at S."))
    cases.append(("single-ip-nomatch",
                  [rule(pkey, direction, state, "", 100, out_of_scope=True)],
                  one_drop(direction, state, 100, when["ip_drop"], hook_filter(pkey, state)),
                  "Out of scope < rule: it provides no pending coverage, so the default policy for S is applied."))
    cases.append(("multi-same-bare",
                  [rule(pkey, direction, state, "", 100),
                   rule(pkey, direction, state, "", 101)],
                  zero_drops(100, when["bare"], hook_filter(pkey, state)),
                  "Two bare < rules at S: the first one accepts."))
    if next_state:
        multi = [rule(pkey, direction, state, "", 100),
                 rule(pkey, direction, next_state, "", 101)]
        multi_pkt = when["bare"]
        multi_hook = hook_filter(pkey, state)
        cases.append(("multi-states", multi, zero_drops(100, multi_pkt, multi_hook),
                      "Two bare < rules at different states: the rule for the earlier state accepts."))
    elif prev_state and prev_state != states[0]:
        # the first state is skipped (progress 0, no valid < rule)
        multi = [rule(pkey, direction, prev_state, "", 100),
                 rule(pkey, direction, state, "", 101)]
        multi_pkt = WHEN[(pkey, direction, prev_state)]["bare"]
        multi_hook = hook_filter(pkey, prev_state)
        cases.append(("multi-states", multi, zero_drops(100, multi_pkt, multi_hook),
                      "Two bare < rules at different states: the rule for the earlier state accepts."))
    other = nearest_content_state(pkey, direction, states, i)
    if other:
        first = kw_part(c, "match") if c else ""
        oc = content(pkey, direction, other)
        cases.append(("multi-match-content-nomatch",
                      [rule(pkey, direction, state, first, 100),
                       rule(pkey, direction, other, kw_part(oc, "nomatch"), 101)],
                      zero_drops(100, when.get("match", when["bare"]) if c else when["bare"],
                                 hook_filter(pkey, state), no_alert=101),
                      "A matching rule for S and a failing keyword rule for another state: the match decides."))
    cases.append(("multi-match-ip-nomatch",
                  [rule(pkey, direction, state, "", 100, out_of_scope=True),
                   rule(pkey, direction, state, "", 101)],
                  zero_drops(101, when["bare"], hook_filter(pkey, state), no_alert=100),
                  "An out of scope rule and a matching bare rule at S: the out of scope rule must not disturb the match."))
    if c and "content_drop" in when and next_state:
        nc = content(pkey, direction, next_state)
        if nc:
            # The non-LTE rule for S + 1 cannot cover S. When the tx advances
            # past S, the failing rule for S resolves in that same pass, so the
            # default policy for S applies and the later match never runs.
            checks = one_drop(direction, state, 100, when["content_drop"], hook_filter(pkey, state))
            checks.append({"filter": {"count": 0, "match": {
                "event_type": "alert", "alert.signature_id": 101}}})
            cases.append(("multi-content-nomatch-next-match",
                          [rule(pkey, direction, state, kw_part(c, "nomatch"), 100),
                           f'accept:flow,alert {pkey}:{next_state} {addr(pkey, direction)} '
                           f'({kw_part(nc, "match")} sid:101;)'],
                          checks,
                          "A failing keyword rule for S and a matching non-LTE rule for S + 1: "
                          "the rule for S resolves when the tx advances past it, so the default "
                          "policy for S applies and the later match cannot rescue the flow."))
            # The first failing rule resolves when the tx advances past S and
            # retires from the coverage accounting, so the second one applies
            # the default policy for S; the later match cannot rescue the flow.
            checks = one_drop(direction, state, 100, when["content_drop"], hook_filter(pkey, state))
            checks.append({"filter": {"count": 0, "match": {
                "event_type": "alert", "alert.signature_id": 101}}})
            checks.append({"filter": {"count": 0, "match": {
                "event_type": "alert", "alert.signature_id": 102}}})
            cases.append(("multi-content-nomatch-same-hook-next-match",
                          [rule(pkey, direction, state, kw_part(c, "nomatch"), 100),
                           rule(pkey, direction, state, kw_part(c, "nomatch"), 101),
                           f'accept:flow,alert {pkey}:{next_state} {addr(pkey, direction)} '
                           f'({kw_part(nc, "match")} sid:102;)'],
                          checks,
                          "Two failing keyword rules for S and a matching non-LTE rule for S + 1: "
                          "the first S rule resolves and retires from the coverage, the second "
                          "applies the default policy for S, and the later match cannot rescue "
                          "the flow."))
    return cases


def write_test(number, pkey, direction, state, slug, rules, checks, note, pcap):
    name = f"ruletype-firewall-{number}-lte-{pkey.replace(':', '-')}-{direction}-{state.replace('_', '-')}-{slug}"
    path = os.path.join(BASE, name)
    os.makedirs(path, exist_ok=True)

    lines = [
        f"# LTE (<hook) state matrix: {pkey} {direction} {state} / {slug}",
        f"# {note}",
        "#",
        "# The packet:filter default policy accepts the session (see suricata.yaml).",
    ]
    if pkey.startswith("http2"):
        lines += [
            "# The last rules are scaffolding: they cover the directions and the",
            "# untested http2 tx type so their default policies do not drop the flow",
            "# before the tested state is reached.",
        ]
    else:
        lines += [
            "# The last rule is scaffolding: it covers the opposite direction so its",
            "# default policy does not drop the flow before this direction reaches S + 1.",
        ]
    lines.append("")
    lines += scaffold(pkey, direction)
    lines.append("")
    lines += rules
    lines.append("")
    with open(os.path.join(path, "firewall.rules"), "w") as f:
        f.write("\n".join(lines))

    with open(os.path.join(path, "suricata.yaml"), "w") as f:
        if pkey.startswith("http2"):
            f.write(SURICATA_YAML_HTTP2)
        elif pkey == "smtp":
            f.write(SURICATA_YAML_SMTP)
        else:
            f.write(SURICATA_YAML)

    test = {
        "requires": {"min-version": 9},
        "args": ["--simulate-ips", "-k none"],
        "pcap": pcap,
        "checks": checks,
    }
    with open(os.path.join(path, "test.yaml"), "w") as f:
        yaml.safe_dump(test, f, sort_keys=False, default_flow_style=False)

    with open(os.path.join(path, "README.md"), "w") as f:
        f.write(f"# {name}\n\n")
        f.write(f"LTE (`<`) state matrix, {pkey} {direction} `{state}`, case `{slug}`.\n\n")
        f.write(f"{note}\n\n")
        if pkey.startswith("http2"):
            f.write("The opposite direction and the untested http2 tx type carry\n"
                    "scaffolding `accept:hook <last-state` rules so their default policies\n"
                    "do not drop the flow before the tested state is reached.\n")
        else:
            f.write("The opposite direction carries one scaffolding `accept:hook <last-state`\n"
                    "rule so its default policy does not drop the flow before this direction\n"
                    "reaches S + 1, where a phase no match becomes final.\n")
    return name


# Package the alert/drop lands on, per (pkey, direction, state):
#   bare         - a bare < rule matches when the state is reached
#   match        - a content rule matches (engine eof / data available)
#   content_drop - a non-matching content rule is decided
#   ip_drop      - an out of scope rule fails the header check
# Read from the phase timeline of the shared pcaps; pinned in the checks.
WHEN = {
    ("http1", "ts", "request_started"): {"bare": 4, "match": 4, "content_drop": 12, "ip_drop": 4},
    ("http1", "ts", "request_line"): {"bare": 4, "match": 6, "content_drop": 6, "ip_drop": 4},
    ("http1", "ts", "request_headers"): {"bare": 6, "match": 10, "content_drop": 10, "ip_drop": 4},
    ("http1", "ts", "request_body"): {"bare": 10, "match": 12, "content_drop": 12, "ip_drop": 4},
    ("http1", "ts", "request_trailer"): {"bare": 12, "ip_drop": 4},
    ("http1", "ts", "request_complete"): {"bare": 12, "ip_drop": 4},
    ("http1", "tc", "response_started"): {"bare": 14, "match": 14, "content_drop": 22, "ip_drop": 14},
    ("http1", "tc", "response_line"): {"bare": 14, "match": 16, "content_drop": 16, "ip_drop": 14},
    ("http1", "tc", "response_headers"): {"bare": 16, "match": 20, "content_drop": 20, "ip_drop": 14},
    ("http1", "tc", "response_body"): {"bare": 20, "match": 22, "content_drop": 22, "ip_drop": 14},
    ("http1", "tc", "response_trailer"): {"bare": 22, "ip_drop": 14},
    ("http1", "tc", "response_complete"): {"bare": 22, "ip_drop": 14},
    ("tls", "ts", "client_started"): {"bare": 4, "match": 6, "content_drop": 6, "ip_drop": 4},
    ("tls", "ts", "client_hello"): {"bare": 6, "match": 6, "content_drop": 6, "ip_drop": 4},
    ("tls", "ts", "client_cert"): {"bare": 6, "match": 6, "content_drop": 22, "ip_drop": 4},
    ("tls", "ts", "client_data"): {"bare": 22, "match": 22, "content_drop": 62, "ip_drop": 4},
    ("tls", "ts", "client_finished"): {"bare": 62, "match": 62, "content_drop": 62, "ip_drop": 4},
    ("tls", "tc", "server_started"): {"bare": 10, "match": 10, "content_drop": 10, "ip_drop": 10},
    ("tls", "tc", "server_hello"): {"bare": 10, "match": 10, "content_drop": 10, "ip_drop": 10},
    ("tls", "tc", "server_cert"): {"bare": 10, "match": 10, "content_drop": 20, "ip_drop": 10},
    ("tls", "tc", "server_data"): {"bare": 20, "match": 20, "ip_drop": 10},
    ("tls", "tc", "server_finished"): {"bare": 20, "ip_drop": 10},
    ("http2:stream", "ts", "request_headers"): {"bare": 5, "match": 5, "content_drop": 14, "ip_drop": 5},
    ("http2:stream", "ts", "request_data"): {"bare": 5, "ip_drop": 5},
    ("http2:stream", "ts", "request_closed"): {"bare": 5, "ip_drop": 5},
    ("http2:stream", "ts", "request_complete"): {"bare": 18, "ip_drop": 5},
    ("http2:stream", "tc", "response_headers"): {"bare": 11, "match": 11, "content_drop": 12, "ip_drop": 8},
    ("http2:stream", "tc", "response_data"): {"bare": 12, "ip_drop": 8},
    ("http2:stream", "tc", "response_closed"): {"bare": 12, "ip_drop": 8},
    ("http2:stream", "tc", "response_complete"): {"bare": 12, "ip_drop": 8},
    ("http2:global", "ts", "request_complete"): {"bare": 4, "ip_drop": 4},
    ("http2:global", "tc", "response_complete"): {"bare": 8, "ip_drop": 8},
    ("smtp", "ts", "request_data"): {"bare": 18, "match": 22, "content_drop": 24, "ip_drop": 6},
    ("smtp", "ts", "request_complete"): {"bare": 24, "ip_drop": 6},
    ("smtp", "tc", "response_data"): {"bare": 20, "ip_drop": 8},
    ("smtp", "tc", "response_complete"): {"bare": 26, "ip_drop": 8},
}

EXCLUDED = {
    ("tls", "tc", "server_finished", "single-bare"),
    ("tls", "tc", "server_finished", "single-content-match"),
    ("tls", "tc", "server_finished", "single-content-nomatch"),
    ("tls", "tc", "server_finished", "multi-same-bare"),
    ("tls", "tc", "server_finished", "multi-match-content-nomatch"),
    ("tls", "tc", "server_finished", "multi-match-ip-nomatch"),
    ("tls", "tc", "server_data", "single-content-nomatch"),
    # The only http2 content state is the earlier headers state, so its no
    # match default fires before the tested state S is reached; the cell has no
    # matching rule for S to decide first.
    ("http2:stream", "ts", "request_data", "multi-match-content-nomatch"),
    ("http2:stream", "ts", "request_closed", "multi-match-content-nomatch"),
    # At the first TLS state the failing rule stays provisional at S + 1 (its
    # tls.version data is not final there), so the later matching rule
    # legitimately accepts before the state default can apply.
}


def excluded(pkey, direction, state, slug):
    return (pkey, direction, state, slug) in EXCLUDED


def main():
    # remove a previous run (the numbering can shift when a case is added)
    import glob
    import shutil
    for d in glob.glob(os.path.join(BASE, "ruletype-firewall-[3-9][0-9][0-9]-lte-http1-*")) + \
            glob.glob(os.path.join(BASE, "ruletype-firewall-[3-9][0-9][0-9]-lte-tls-*")) + \
            glob.glob(os.path.join(BASE, "ruletype-firewall-[3-9][0-9][0-9]-lte-http2-*")) + \
            glob.glob(os.path.join(BASE, "ruletype-firewall-[3-9][0-9][0-9]-lte-smtp-*")):
        shutil.rmtree(d)

    number = START
    names = []
    # The cells added later are numbered after the pre-existing ones so their
    # test directories keep their numbers.
    added_later = {"multi-content-nomatch-next-match",
                   "multi-content-nomatch-same-hook-next-match"}
    # The pre-existing protocols keep their numbers: run every pass for them
    # before the http2 cells are appended.
    groups = ([p for p in PROTOCOLS if not p[0].startswith("http2") and p[0] != "smtp"],
              [p for p in PROTOCOLS if p[0].startswith("http2")],
              [p for p in PROTOCOLS if p[0] == "smtp"])
    for group in groups:
        for pass_slug in (False, "multi-content-nomatch-next-match",
                "multi-content-nomatch-same-hook-next-match"):
            for pkey, direction, states, pcap in group:
                for state in states:
                    if state == states[0]:
                        continue
                    for slug, rules, checks, note in cases_for(pkey, direction, state, states):
                        if excluded(pkey, direction, state, slug):
                            continue
                        if pass_slug is False:
                            if slug in added_later:
                                continue
                        elif slug != pass_slug:
                            continue
                        names.append(write_test(number, pkey, direction, state, slug,
                                                rules, checks, note, pcap))
                        number += 1
    print(f"wrote {len(names)} tests")


if __name__ == "__main__":
    main()
