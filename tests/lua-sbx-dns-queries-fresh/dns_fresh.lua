-- control: read the accessor on the live tx each time (no caching)
local dns = require('suricata.dns')
local slog = require('suricata.log')
function init(args)
    local needs = {}
    needs['protocol'] = 'dns'
    return needs
end
function setup(args) end
function log(args)
    local tx = dns.get_tx()
    if tx == nil then return 0 end
    -- the live tx is always valid; the guard must not raise
    local ok, err = pcall(function() return tx:queries() end)
    if not ok then
        slog.error("sbx-fresh-uaf: live read unexpectedly failed: " .. tostring(err))
    else
        slog.warning("sbx-fresh-uaf: live read ok")
    end
    return 0
end
function deinit(args) return 0 end
