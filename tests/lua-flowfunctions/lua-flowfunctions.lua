-- simple output test for some lua flow lib functions
name = "flow_http_lua.log"

local flow = require("suricata.flow")

function init (args)
    local needs = {}
    needs["type"] = "flow"
    needs["protocol"] = "http"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("Log Filename " .. filename)
    http = 0
end

function log(args)
    local f = flow.get()
    ts = f:timestring_iso8601()
    has_alerts = f:has_alerts()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()
    alproto, alproto_ts, alproto_tc, alproto_orig, alproto_expect = f:app_layer_proto()
    start_sec, start_usec, last_sec, last_usec = f:timestamps()
    id = f:id()
    id_str = string.format("%.0f", id)

    if has_alerts then
        file:write ("[**] Start time " .. ts .. " [**] -> alproto " .. alproto .. " [**] " .. proto .. " [**] alerted: true\n[**] First packet: " .. start_sec .." [**] Last packet: " .. last_sec .. "\n")
        file:flush()
    end
end

function deinit (args)
    SCLogInfo ("HTTP logged: " .. http);
    file:close(file)
end
