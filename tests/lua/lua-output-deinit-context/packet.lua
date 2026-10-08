-- keep the packet handle from log() and use it from deinit(): the engine
-- has destroyed the thread's packet pool by then, so the handle must fail
-- closed (nil plus an error), not read the freed packet
local packet = require("suricata.packet")
local config = require("suricata.config")

function init(args)
    local needs = {}
    needs["type"] = "packet"
    return needs
end

function setup(args)
    last = nil
end

function log(args)
    last = packet.get()
end

function deinit(args)
    local f = assert(io.open(config.log_path() .. "/deinit-packet.log", "w"))
    local sec, err = last:timestamp()
    f:write("timestamp: " .. tostring(sec) .. " " .. tostring(err) .. "\n")
    f:close()
end
