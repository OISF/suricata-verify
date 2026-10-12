# http1-state-hook-buffer-timing

Checks when a rule with an app-layer state hook above its buffer is evaluated.

`http.header` completes in the request headers state, the hook is the request trailer
state. The buffer engine runs from its own state on, so the alert must land on the packet
that carries the header lines, before the trailer block exists. This is the behaviour the
relaxed load-time check in the engine branch allows; before it, the rule did not load at
all ("engine progress value 2 doesn't match hook 4").

That the buffer no longer grows at the trailer state, which is what stops the rule from
matching a second time, is covered by the `count: 0` leak rules in tests/http1-trailer.
