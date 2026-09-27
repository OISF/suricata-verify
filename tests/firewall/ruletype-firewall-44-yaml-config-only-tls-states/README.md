Test to check if loading firewall mode and rules purely through the yaml works.

Empty test.rules is needed to avoid SV adding `--disable-detection`.

Firewall rules are in a subdir to avoid SV loading it as a regular rulefile.

Ticket #8206 (https://redmine.openinfosecfoundation.org/issues/8206)
