-- each of these must raise "Blocked Lua function called: ..."
local log = require('suricata.log')
function init(args) return {} end
function thread_init(args) return {} end
function match(args)
    local ok
    ok, _ = pcall(io.open, '/tmp/x', 'w')
    ok, _ = pcall(os.time)
    ok, _ = pcall(loadstring, 'return 1')
    ok, _ = pcall(string.rep, 'A', 2)  -- control: allowed
    log.warning("stubs checked")
    return 0
end
