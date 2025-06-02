local flow = require "suricata.flow"
local logger = require("suricata.log")
local config = require "suricata.config"

function init (args)
    return {streaming = "http"}
end

function setup (args)
    filepath = config.log_path()
end

function log(args)
    f = flow.get()
    ts = f:timestring_legacy()
    ipver, srcip, dstip, proto, sp, dp = f:tuple()
    local stream = args["stream"]
    logger.notice("called with data_open " .. tostring(stream["open"]) .. " data_close " .. tostring(stream["close"]) .. " to_server " .. tostring(stream["to_server"]) .. " to_client " .. tostring(stream["to_client"]));
    filename = filepath .. "/http-" .. proto .. "-" .. srcip .. "-" .. dstip .. "-" .. sp .. "-" .. dp

    file_mode = "a"
    if (data_open == true) then
        file_mode = "w"
    end

    file = assert(io.open(filename, file_mode))
    file:write (stream["data"])
    file:flush()
    file.close(file)
end

function deinit (args)
end
