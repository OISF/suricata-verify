local flow = require "suricata.flow"
local logger = require("suricata.log")
local config = require "suricata.config"

function init (args)
    local needs = {}
    needs["type"] = "streaming"
    needs["protocol"] = "http"
    return needs
end

function setup (args)
    filepath = config.log_path()
end

function log(args)
    f = flow.get()
    ts = f:timestring_legacy()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()
    data, data_open, data_close = SCStreamingBuffer()
    logger.notice("called with data_open " .. tostring(data_open) .. " data_close " .. tostring(data_close));
    filename = filepath .. "/http-" .. proto .. "-" .. srcip .. "-" .. dstip .. "-" .. sp .. "-" .. dp

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
