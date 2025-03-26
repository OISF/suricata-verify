-- simple fast-log to file lua module
local packet = require "suricata.packet"
local flow = require("suricata.flow")
local http = require("suricata.http")

name = "http_lua.log"

function init (args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    http_tx = 0
end

function log(args)
    local tx = http.get_tx()
    http_uri = tx:request_raw_uri()
    if http_uri == nil then
        http_uri = "<unknown>"
    end
    http_uri = string.gsub(http_uri, "%c", ".")

    http_host = tx:request_host()
    if http_host == nil then
        http_host = "<hostname unknown>"
    end
    http_host = string.gsub(http_host, "%c", ".")

    http_ua = tx:request_header("User-Agent")
    if http_ua == nil then
        http_ua = "<useragent unknown>"
    end
    http_ua = string.gsub(http_ua, "%c", ".")

    p = packet.get()
    ts = p:timestring_legacy()
    f = flow.get()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()

    file:write (ts .. " " .. http_host .. " [**] " .. http_uri .. " [**] " ..
           http_ua .. " [**] " .. srcip .. ":" .. math.floor(sp) .. " -> " ..
           dstip .. ":" .. math.floor(dp) .. "\n")
    file:flush()

    http_tx = http_tx + 1
end

function deinit (args)
    SCLogInfo ("HTTP transactions logged: " .. http_tx);
    file:close(file)
end
