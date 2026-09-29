-- caches the handle of the first transaction and touches it from the next one
local dns = require('suricata.dns')
local slog = require('suricata.log')
local cached, n = nil, 0
function init(args)
    local needs = {}
    needs['protocol'] = 'dns'
    return needs
end
function setup(args) end
function log(args)
    n = n + 1
    local tx = dns.get_tx()
    if tx == nil then return 0 end
    local h = cached or tx
    -- pcall the accessor: before the fix a freed handle silently returns
    -- stale data (UAF); after the fix the liveness guard raises.
    local ok, err = pcall(function() return h:queries() end)
    if not ok then
        slog.error("sbx-cached-uaf: guard raised as expected: " .. tostring(err))
    else
        slog.warning("sbx-cached-uaf: stale read succeeded (UAF): " .. tostring(err))
    end
    if cached == nil then cached = h end
    return 0
end
function deinit(args) return 0 end
