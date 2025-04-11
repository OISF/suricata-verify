# Test Description

ASAN-only

Validate that memory is released for string variables used in Lua scripts

## PCAP

Redmine issue 7466: https://redmine.openinfosecfoundation.org/issues/7466

## Related issues

Configure with `CC="clang" LDFLAGS="-fsanitize=address" CFLAGS="-Wshadow -fsanitize=address -fno-omit-frame-pointer" ./configure`
Then run with `ASAN_OPTIONS="detect_leaks=1" python3 ../suricata-verify/run.py lua-memleak`
