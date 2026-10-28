# Stable uncounted pass verdict with alert context

Redmine #9116, backport #9223.

An alert rule and a pass rule each capture the UDP payload with a pcre
`alert:` capture. The action order puts alert before pass, as in the
`bug-5464-verdict` tests. These UDP payload rules pass only the current
packet, so all 20 packets exercise the path.

On 8.0.x, EVE verdict logging reads the uncounted `alerts[cnt].action`
slot to report the pass verdict on an earlier counted alert. That sentinel
must remain present but must not own JSON context: the pass rule's capture
stays owned by the detection queue until cleanup. Otherwise verdict logging
regresses, or the uncounted capture is leaked or freed twice.

The test pins all 20 counted alerts to their own packet's capture and a pass
verdict. Neither the pass signature nor its distinct capture may be logged.
A sanitizer build with leak detection must also exit successfully; the normal
runner exit check must not be disabled to hide ownership errors.

## PCAP provenance

References `../rule-limit-pcre-alert-context/input.pcap` without copying it.
Its retained generator, `../rule-limit-pcre-alert-context/create-pcap.py`,
uses scapy to create one UDP flow of 20 packets carrying `id=abc00` through
`id=abc19`. No new PCAP is generated.

This is a stable-only guard because main does not use the same uncounted
pass-sentinel contract.
