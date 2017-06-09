#! /bin/sh

# Skip this test if Rust is enabled. Rust does not handle the non-eve
# DNS log.
if ./src/suricata --build-info | grep Rust | grep -q yes; then
    exit 0
fi

exit 1
