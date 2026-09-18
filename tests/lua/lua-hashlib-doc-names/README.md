Reproducer for the hashlib documentation: doc/userguide/lua/libs/hashlib.rst
documents sha256_hex_digest/sha1_hex_digest/md5_hex_digest, but the code
registers sha256_hexdigest/sha1_hexdigest/md5_hexdigest. Copy-pasting the
documented example fails with "attempt to call a nil value".

The check fails while the docs use the wrong spelling and passes once
the docs match the registered names.

Ticket: #9077.
