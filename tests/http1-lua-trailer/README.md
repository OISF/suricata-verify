Lua output script reading HTTP trailer fields of a transaction through the
tx:request_trailer(), tx:request_trailers() and *_raw accessors, both directions.

Needs the trailer buffers, so it is expected to fail before the engine side lands.
