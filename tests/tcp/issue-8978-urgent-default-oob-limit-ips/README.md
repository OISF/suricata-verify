# Missing TCP urgent OOB limit policy defaults to drop

Redmine #8978, backport #8990.

The local configuration sets `stream.reassembly.urgent.policy` to `oob`
but deliberately omits `stream.reassembly.urgent.oob-limit-policy`.
Exceeding the OOB byte limit must drop the remaining urgent packets,
rather than silently falling back to inline treatment.

The assertions retain the explicit-drop control's alert counts, parsed
HTTP URI, accepted and dropped packet counts, urgent count and gap count.
They distinguish the missing-key fallback from the old inline behavior.

## PCAP and rules

Reuses upstream's `../../tcp-urgp-07-oob-exceed-limit/tcp-urgent-1byte-66k.pcap`
and `suricata.rules`. The existing test supplies the explicit-policy
control. No new capture is generated.
