# Test Purpose

Test that a pcre capture into a flow variable does not abort the process when
the matching packet has no flow.

`DetectPcrePayloadMatch` dispatches every capture group on `pe->captypes[x]`,
and the flow-variable arm used to carry an extra runtime predicate:

```c
} else if (pe->captypes[x] == VAR_TYPE_FLOW_VAR && f != NULL) {
```

The chain was written as if it were exhaustive over the four capture types the
rule parser can produce, so it ended in `else { BUG_ON(1); }`. With
`captypes[x] == VAR_TYPE_FLOW_VAR` and `f == NULL` the conjunction is false,
the remaining arms do not match, and the "impossible" case aborts the whole
process -- `assert()` wherever assert.h is available and `NDEBUG` is unset,
which is the ordinary build, and `exit(EXIT_FAILURE)` otherwise.

A rule reaches that state from the wire because nothing keeps a flow-variable
capture away from a flowless packet: `SignatureCreateMask` sets
`SIG_MASK_REQUIRE_FLOW` for the flow-scoped keywords -- `flowbits`, `flowint`,
`config` with flow scope, app-layer signatures and anything setting
`SIG_FLAG_INIT_FLOW` -- but not for `pcre`, and not for the
`DETECT_FLOWVAR_POSTMATCH` sigmatch that a capture appends.

`bug-8862-01` uses an ICMPv4 destination-unreachable message, which
`FlowCreateCheck` refuses to give a flow while `DecodeICMPV4` still fills in
`p->payload`. `bug-8862-02` denies a flow to an ordinary UDP packet with
`--simulate-packet-flow-memcap`, which returns before `FlowGetNew` consults
the real memcap: it reproduces the flowless packet rather than the memcap
path the report describes.

Both tests also check what has to keep working: the signatures still alert on
the flowless packets, and captures that do not need a flow (pktvars, alert
vars) are still stored, including in a rule where a dropped flow capture is
followed by a pktvar capture. `bug-8862-01` additionally checks that flow
variables are still stored for the packet that does have a flow.

The `not-has-key: metadata.flowvars` checks cannot fail while the packets
stay flowless, since `EveAddMetadata` only emits flowvars for a flow. They
pin the premise rather than the fix: if an ICMPv4 error message or a
memcap-denied packet ever gained a flow, these tests would stop exercising
the defect, and those checks are what would say so.

Redmine ticket: https://redmine.openinfosecfoundation.org/issues/8862
