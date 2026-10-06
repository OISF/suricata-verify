# SWF decompression truncation

The pcap returns a compressed `CWS` SWF whose `FileLength` header is `1` but
whose body decompresses to 153 bytes containing `EVIL_FLASH_EXPLOIT_MARKER`.

A vulnerable engine sizes the output buffer from that header value, decompresses
a single byte, and never sees the marker, so signature `1` does not fire.

Ticket: https://redmine.openinfosecfoundation.org/issues/8855
