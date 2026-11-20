# Redmine feature 9205 — real traffic, no attacker

Excerpt (230 data segments, first ~1,500 packets) of `Control/control/testing/frequent/master.pcap` from
the 2017QUT_DNP3 dataset (github.com/qut-infosec/2017QUT_DNP3; N. R. Rodofile, K. Radke, E. Foo,
"Framework for SCADA cyber-attack dataset creation", ACSW 2017), used with the authors' permission. The
master–outstation connection is already established when the capture starts (no handshake), so the test
enables `stream.midstream`. Every frame is logged and no event is raised under the default setting.
