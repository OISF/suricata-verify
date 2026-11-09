Reproducer for lua: the engine-log API allows an out of bounds stack
read. SCLogMessageJSON() copies MIN(buffer_size, SCJbLen(js)) bytes into
the caller's fixed 12800 byte stack buffer without reserving room for a
NUL terminator, so when a log message is long enough for the JSON render
to be clamped the buffer is left unterminated. The stream and syslog
sinks then consume it as a C string and scan past the end of the buffer.

The output script logs a 20000 byte message, which makes the JSON render
(truncated message plus framing) exceed the buffer. With the bug the
resulting suricata.log line is 12800+ bytes (ASAN: stack-buffer-overflow
in fprintf); with the render terminated at buffer_size - 1 no line can
exceed 12799 bytes.

Ticket: #9048.
