-- simple SCFlowTuple log test
name = "scflow-tuple.log"

function init(args)
    local needs = {}
    needs["type"] = "flow"
    return needs
end

function setup(args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("Lua SCFlowTuple Log Filename " .. filename)
    flow = 0
    version = _VERSION
end

function log(args)
    startts = SCFlowTimeString()
    ipver, srcip, dstip, proto, sp, dp = SCFlowTuple()
    proto_string = SCFlowAppLayerProto()

    file:write ("{" .. startts .. " [**]\nSCFlowTuple is\nIP Version:  " .. ipver .. "\nSrc: " .. srcip .. ":" .. sp .. " -> Dst: " .. dstip .. ":" .. dp .. " [**] Protocol: " .. proto_string .. "(" .. proto .. ")}\n")
    file:flush()
    flow = flow + 1
end

function deinit(args)
    SCLogInfo ("Lua version is " .. version);
    SCLogInfo ("Flow tuples logged: " .. flow);
    file:close(file)
end
