# Redmine issue 9126

This test covers using a 64-bit value extracted with `byte_extract` as the
`within` value of a subsequent content match.

The UDP payload contains a decimal value of 4294967300 followed by `EVIL`.
Signature 1 extracts that value and uses it as the `within` window, so `EVIL`
should match. Signatures 2 and 3 are controls proving that `EVIL` is present
and reachable.

On affected versions, the extracted value is truncated to 32 bits when the
content inspection window is calculated. The value becomes 4 and signature 1
does not alert, while both control signatures alert.

Based on the reproducer supplied by the reporter for
https://redmine.openinfosecfoundation.org/issues/9126.
