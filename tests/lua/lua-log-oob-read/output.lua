local config = require("suricata.config")
local logger = require("suricata.log")

function init(args)
    local needs = {}
    needs["type"] = "packet"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))

    -- A message longer than the 12800 byte SCLog buffer, so the JSON
    -- render (message + framing) is clamped to buffer_size.
    logger.notice(string.rep("A", 20000))

    file:write("logged\n")
    file:flush()
end

function log(args)
end

function deinit()
    file:close()
end
