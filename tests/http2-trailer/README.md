# HTTP/2 trailer buffers

A gRPC shaped stream: request HEADERS, a DATA frame, the response, then a trailer HEADERS
block that reuses `user-agent` and adds `grpc-message` and `server-timing`.

The trailer fields must be reachable through `http.trailer`, `http.trailer.raw` and
`http.trailer_names`, and must not be reachable through `http.header`, `http.header.raw`,
`http.header_names` or `http.user_agent`. One rule keeps its fast pattern in the header
section and matches content in the trailer section.

Before the trailer state existed, no rule could match this trailer block at all: the header
state it was reported in had already been declared complete.
