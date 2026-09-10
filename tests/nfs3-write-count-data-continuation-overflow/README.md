# WRITE continuation overflow with count > file_len: the stream must
# land on the following RPC

NFSv3 with max-write-queue-size 1024: an in-order 100-byte WRITE
(fh3), then a fragmented WRITE on the same handle at offset 8192 with
count 4096 but file_len 2048 (data_len < count). The file_len-based
chunk promise is 1536 (2048 - the 512 buffered); the continuation
crosses the queue limit (512 buffered OOO + 1536 promised > 1024) and
the chunk path rejects it; the count-based promise (3584) would have
projected the overflow onto bytes the parser never buffers. The
consume/skip must follow the record's unbuffered tail (file_len-based),
else it runs into the following RPC (a complete 1000-byte WRITE on a
second handle) and the stream desyncs. Checks: the queue event is
attributed to the file's tx (tx_id 0), no malformed data, the
following WRITE's file is still logged (size 1000).
