Test the logging of IKEv1 records in the presence of duplicate proposals.

Ticket: https://redmine.openinfosecfoundation.org/issues/7902

## PCAP

Based on the the PCAP found in tests/ikev1-rules/ikev1-isakmp-main-mode.pcap (md5sum: e7e6d064e402997e81ea26b481963731):
- First packet was extracted
- LLM used to generate scapy script to create identical packet, then add duplicate proposal
