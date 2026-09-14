# smb2-write-too-large

Pins the SMB2 WRITE length-vs-record check.

Synthetic capture: two SMB2 WRITE request records sharing one file GUID.

- w1 offset 0, declared length 100, 100 bytes buffered: in order, stored.
- w2 declares 300 bytes but the NBSS record only carries 100: the
  request is refused with `applayer/smb/write_request_too_large`, the
  remainder of the record is skipped and the flow is not errored.

The stored file only holds w1 (100 x 0x41): the refused write never
touched the file and no follow-on data was misattributed.
