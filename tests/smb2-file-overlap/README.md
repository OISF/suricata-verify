# smb2-file-overlap

Pins the SMB2 file data overlap behavior.

Synthetic capture: two SMB2 WRITE request records sharing one file GUID.

- w1 offset 0, length 100: in order, tracked becomes 100.
- w2 offset 50, length 100: 50 < tracked -- `applayer/smb/file_overlap`
  is set on the file transaction; the already-covered prefix is dropped
  and the uncovered tail (50 bytes) is re-anchored at the tracked
  offset and stored.

The stored file is 150 bytes: A*100 followed by the un-covered tail of
the overlapping write.
