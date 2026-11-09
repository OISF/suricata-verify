-- battery: exercise multiple dns accessors on the live tx (no caching)
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
    local ok, err = pcall(function()
        local q = tx:queries()
        local a = tx:answers()
    end)
    if not ok then
        slog.error("sbx-applayer-uaf: live accessors failed: " .. tostring(err))
    else
        slog.warning("sbx-applayer-uaf: accessors ok")
    end
    return 0
end
function deinit(args) return 0 end
