# SMB2 file logging: sha256 of a downloaded MTA attachment

Real capture (extract from a QA run): a mail client downloads the VBS
attachment SH-20180404-B92D36.vbs (4733 bytes, per the create
response's EndOfFile) over SMB2 (dialect 2.02, length-prefixed
records) from an MTA. The file is opened/read/closed seven times;
three full 4733-byte reads, two 512-byte partial reads and one
4096-byte read (merged into the file tx of the last transaction).

Checks: file logging enabled (filestore), the three full-file
transactions log the 4733-byte file and the two partial-read
transactions log the 512-byte prefix, all with the sha256 of the
actual wire data (independently extracted from the capture), no
gaps. Two file transactions carry repeated reads of the same
offset range (one file read fully twice, one read 4096 bytes then
4733) and are reported as file_overlap; no other anomalies.
