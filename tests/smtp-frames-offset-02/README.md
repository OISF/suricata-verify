# Test Description

Frames must still be logged after the stream has released data.

Uses the pcap of `smtp-frames-offset-01`: an SMTP session with two
messages. With the eve `frame` logger enabled, both `smtp.data` frames
(stream offsets 46 and 3401) get a `frame` record. Before the fix, the
frame logger added the stream base offset to the frame offset, which is
already absolute, so every frame from the first message's data frame on
was pruned without a record.

## Redmine ticket

https://redmine.openinfosecfoundation.org/issues/9446
