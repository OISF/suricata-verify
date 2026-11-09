Reproducer for lua/base64: SCBase64Decode() returns 0 for len == 0 and
for real decode errors, so the C wrapper raises "base64 decoding
failed" for empty input. decode("") and the four other decode variants
must return "" for empty input.

The script asserts the empty-input result for all five modes plus
encode(""). With the bug the first call raises and the rule never
alerts.

Ticket: #9075.
