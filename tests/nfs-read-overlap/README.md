NFSv3 READ reply overlapping tracked data
=========================================

A client reads 100 bytes at offset 0 without eof, so the file transaction stays
open with 100 bytes tracked, then reads 50 bytes at offset 50. The second reply
starts inside data the tracker already holds, which is `file_overlap` - the read
path applies the same high-water rule as the write paths.

The record shows offset 0 (the read that opened the transaction), size 150 -
the bytes both replies carried, so the overlap counts twice - and two chunks,
because a read logs one chunk per reply record. `fileinfo.size` stays at 100,
which is what the tracker kept.

`gen.py` writes `input.pcap`. Regenerate with `python3 gen.py`.
