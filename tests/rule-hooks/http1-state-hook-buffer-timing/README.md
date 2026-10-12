# http1-state-hook-buffer-timing

Checks when a rule with an app-layer state hook above its buffer is evaluated.

`http.header` completes in the request headers state, the hook is the request trailer
state. The buffer engine runs from its own state on, so the alert must land on the packet
that carries the header lines, before the trailer block exists. This is the behaviour the
relaxed load-time check in the engine branch allows; before it, the rule did not load at
all ("engine progress value 2 doesn't match hook 4").

The rule fires again at the trailer packet on this branch: the trailer fields still share the
header buffer storage, so the buffer grows after the headers state and the pattern matches a
second time. With trailer buffers of their own that second match disappears, and the trailer
work's companion test asserts it is gone.
