-- fast.log style output test for suricata.flow lua lib
name = "lua-scflowstats.log"

local flow = require("suricata.flow")
local logger = require("suricata.log")
local config = require("suricata.config")

function init(args)
    local needs = {}
    needs["type"] = "flow"
    return needs
end

function setup(args)
    filename = config.log_path() .. "/" .. name
    file = assert(io.open(filename, "a"))
    logger.info("lua SCFlowStats Log Filename " .. filename)
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
