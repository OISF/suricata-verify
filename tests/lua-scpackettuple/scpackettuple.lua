-- simple SCPacketTuple log test
name = "scpacket-tuple.log"

function init(args)
    local needs = {}
    needs["type"] = "packet"
    return needs
end

function setup(args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("Lua SCPacketTuple Log Filename " .. filename)
    packets = 0
    version = _VERSION
end

function log(args)
    timestring = SCPacketTimeString()
    ipver, srcip, dstip, proto, sp, dp = SCPacketTuple()
    
    file:write ("{" .. timestring .. " [**]\nSCPacketTuple is\nIP Version:  " .. ipver .. "\nSrc: " .. srcip .. ":" .. sp .. " -> Dst: " .. dstip .. ":" .. dp .. " [**] Protocol: " .. proto .. "}\n")
    file:flush()
    packets = packets + 1
end

function deinit(args)
    SCLogInfo("Lua version is: " .. version);
    SCLogInfo ("Packets logged: " .. packets);
    file:close(file)
end
