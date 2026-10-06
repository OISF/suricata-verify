-- Use a sha256 hasher after finalize_to_hex() has consumed it.
--
-- finalize_to_hex() consumes the Rust hash context and the C binding sets the inner
-- pointer to NULL. The following finalize_to_hex() must detect that NULL inner pointer and
-- raise a Lua error. If it only checks the outer userdata pointer (which
-- luaL_checkudata never returns as NULL), NULL crosses the FFI boundary and
-- the engine dies with SIGSEGV.

local hashlib = require("suricata.hashlib")

function init(args)
    return {}
end

function match(args)
    local hasher = hashlib.sha256()
    hasher:update("www.suricata-ids.org")
    hasher:finalize_to_hex()

    -- Must raise a Lua error rather than crash the process.
    hasher:finalize_to_hex()

    -- Not reached: the call above is expected to raise.
    return 1
end
