Test that IMAP event 'body-too-large' is set when an email body is larger than its limit.

A FETCH response contains an early body, 2,000 empty literals, and a late
body. The cumulative metadata exceeds the parser's 8 KiB line limit while
literal payloads remain well below the email retention limit.

The parser must report the limit, retain only the early body, and still
create the late body's frame. The tagged completion and a subsequent NOOP
must parse successfully. Traffic is segmented and reassembly depth is
unlimited so a stream-depth cutoff cannot hide the problem.

