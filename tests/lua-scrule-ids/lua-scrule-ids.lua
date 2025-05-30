-- lua_pushinteger output test for SCRuleIds and ...
local packet = require "suricata.packet"
local rule = require "suricata.rule"
local logger = require "suricata.log"

name = "lua-scrule-ids.log"

function init(args)
    return {
        type = "packet",
        filter = "alerts",
    }
end

function setup(args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    logger.info("lua SCRuleIds Log Filename " .. filename)
end

function log(args)
    p = packet.get()
    timestring = p:timestring_legacy()
    local sig = rule.get_rule()
    local sid = sig:sid()
    local rev = sig:rev()
    local gid = sig:gid()

    file:write ("[**] " .. timestring .. "\nSCRuleIds is\n[**]\nSignature id: " .. sid .. "\nrevision: " .. rev .. "\nGroup id: " .. gid .. "[**]")
    file:flush()
end

function deinit(args)
    file:close(file)
end
