A chunked message whose chunks are all delivered but that is never closed by
"BDAT <n> LAST": the sender moves on to a new envelope. The abandoned message
must be reported and closed, so the next one gets its own transaction and its
body inspected.
