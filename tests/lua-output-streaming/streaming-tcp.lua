function init (args)
    local needs = {}
    needs["type"] = "streaming"
    needs["filter"] = "tcp"
    return needs
end

function setup (args)
    filepath = SCLogPath()
    alerts = 0
end

function log(args)
    ts = SCFlowTimeString()
    ipver, srcip, dstip, proto, sp, dp = SCFlowTuple()
    data, data_open, data_close = SCStreamingBuffer()
    filename = filepath .. "/" .. proto .. "-" .. srcip .. "-" .. dstip .. "-" .. sp .. "-" .. dp

    file_mode = "a"
    if (data_open == true) then
        file_mode = "w"
    end

    file = assert(io.open(filename, file_mode))
    file:write (data)
    file:flush()
    file.close(file)
end

function deinit (args)
end
