Untagged FETCH responses go to the pipelined FETCH whose sequence set
includes their number. Each set is parsed once when its command is stored,
so 5,000 responses do not walk the 32 pending 8 KiB sets again on every line.
A set with 64 ranges, the most kept, is still matched exactly.
A set truncated with its line is not used to rule out a response, since the
cut may fall inside a number.
Nor is a set used to rule out a sequence number too large to parse.
Response lines are inspected as they arrive, not once the tagged reply
completes the command.
