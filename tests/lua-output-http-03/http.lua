-- simple fast-log to file lua module
local flow = require("suricata.flow")
local packet = require "suricata.packet"
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
    SCLogInfo("HTTP Log Filename " .. filename)
    http_tx = 0
end

function log(args)
    local tx = http.get_tx()
    http_uri = tx:request_uri_normalized()
    if http_uri == nil then
        http_uri = "<unknown>"
    end

    http_request_headers = tx:request_headers_raw()
    if http_request_headers == nil then
        http_request_headers = "<hostname unknown>"
    end

    http_response_headers = tx:response_headers_raw()
    if http_response_headers == nil then
        http_response_headers = "<hostname unknown>"
    end

    p = packet.get()
    ts = p:timestring_iso8601()
    f = flow.get()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()

    file:write (ts .. "\n\n" .. "URI: " .. http_uri .. "\n" ..
                "\nREQUEST\n" .. ".......\n" .. http_request_headers .. "\nRESPONSE\n" .. "........\n" .. http_response_headers .. "\n")
    file:flush()

    http_tx = http_tx + 1
end

function deinit (args)
    SCLogInfo ("HTTP transactions logged: " .. http_tx);
    file:close(file)
end
