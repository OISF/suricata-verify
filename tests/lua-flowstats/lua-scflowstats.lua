-- fast.log style output test for suricata.flow lua lib
name = "lua-scflowstats.log"

local flow = require("suricata.flow")

function init(args)
    local needs = {}
    needs["type"] = "flow"
    return needs
end

function setup(args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("lua SCFlowStats Log Filename " .. filename)
end

function log(args)
    local f = flow.get()
    timestring = f:timestring_legacy()
    tscnt, tsbytes, tccnt, tcbytes = f:stats()

   file:write ("[**] " .. timestring .. "\nSCFlowStats is\nPacket count to server:  " .. tscnt .. "\nByte count to server: " .. tsbytes .. "\nPacket count to client: " .. tccnt .. "\nByte count to client: " .. tcbytes .. "\n[**]")
    file:flush()
end

function deinit(args)
    file:close(file)
end
