-- simple SCFlowTuple log test
local flow = require("suricata.flow")

name = "scflow-tuple.log"

function init(args)
    local needs = {}
    needs["type"] = "flow"
    return needs
end


function setup(args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogNotice("lua SCFlowTuple Log Filename " .. filename)
end

function log(args)
    f = flow.get()
    startts = f:timestring_iso8601()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()
    alproto, alproto_ts, alproto_tc, alproto_orig, alproto_expect = f:app_layer_proto()

    file:write ("{" .. startts .. " [**]\nSCFlowTuple is\nIP Version:  " .. ipver .. "\nSrc: " .. srcip .. ":" .. sp .. " -> Dst: " .. dstip .. ":" .. dp .. " [**] Protocol: " .. alproto .. "(" .. proto .. ")" .. " alproto_orig: " .. alproto_orig .. " alproto_expect:  " .. alproto_expect .. "}\n")
    file:flush()
end

function deinit(args)
    file:close(file)
end
