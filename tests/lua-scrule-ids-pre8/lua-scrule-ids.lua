-- lua_pushinteger output test for SCRuleIds and ...
name = "lua-scrule-ids.log"

function init(args)
    local needs = {}
    needs["type"] = "packet"
    needs["filter"] = "alerts"
    return needs
end

function setup(args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("lua SCRuleIds Log Filename " .. filename)
end

function log(args)
    timestring = SCPacketTimeString()
    sid, rev, gid = SCRuleIds()

    file:write ("[**] " .. timestring .. "\nSCRuleIds is\n[**]\nSignature id: " .. sid .. "\nrevision: " .. rev .. "\nGroup id: " .. gid .. "[**]")
    file:flush()
end

function deinit(args)
    file:close(file)
end
