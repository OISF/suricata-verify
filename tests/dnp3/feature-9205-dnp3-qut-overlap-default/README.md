# Redmine feature 9205 — real attack traffic, option off

Excerpt (113 packets around frames 113600–113760, TCP port 57777) of
`Attacks/attacks/testing/infrequent/master.pcap` from the 2017QUT_DNP3 dataset
(github.com/qut-infosec/2017QUT_DNP3; N. R. Rodofile, K. Radke, E. Foo, "Framework for SCADA cyber-attack
dataset creation", ACSW 2017), used with the authors' permission. The attacker's segment overlaps the
outstation's in sequence space with different octets, so the reassembled to-client stream contains the
tail of one frame where the next should begin. With `resync-on-bad-start` off (the shipped behaviour),
DNP3 inspection of the flow ends there and no event is raised: one transaction is logged out of twelve.
`feature-9205-dnp3-qut-overlap-resync` runs the same capture with the option on.
