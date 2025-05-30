local packet = require "suricata.packet"
local logger = require("suricata.log")
local config = require "suricata.config"

-- simple SCPacketTuple log test
name = "scpacket-tuple.log"

function init(args)
    local needs = {}
    needs["type"] = "packet"
    return needs
end

function setup(args)
    filename = config.log_path() .. "/" .. name
    file = assert(io.open(filename, "a"))
    logger.info("Lua SCPacketTuple Log Filename " .. filename)
    packets = 0
end

function log(args)
    p = packet.get()
    timestring = p:timestring_legacy()

    ipver, srcip, dstip, proto, sp, dp = p:tuple()

    file:write ("{" .. timestring .. " [**]\nSCPacketTuple is\nIP Version:  " .. ipver .. "\nSrc: " .. srcip .. ":" .. sp .. " -> Dst: " .. dstip .. ":" .. dp .. " [**] Protocol: " .. proto .. "}\n")
    file:flush()
    packets = packets + 1
end

function deinit(args)
    logger.info ("Packets logged: " .. packets);
    file:close(file)
end
