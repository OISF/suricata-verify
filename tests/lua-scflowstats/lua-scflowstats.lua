local io = require("io")
-- lua_pushinteger output test for SCFlowStats and ...
name = "lua-scflowstats.log"

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
    timestring = SCFlowTimeString()
    tscnt, tsbytes, tccnt, tcbytes = SCFlowStats()

   file:write ("[**] " .. timestring .. "\nSCFlowStats is\nPacket count to server:  " .. tscnt .. "\nByte count to server: " .. tsbytes .. "\nPacket count to client: " .. tccnt .. "\nByte count to client: " .. tcbytes .. "\n[**]")
    file:flush()
end

function deinit(args)
    file:close(file)
end
