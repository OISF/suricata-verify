local config = require("suricata.config")

function init(args)
    -- boolean key in the needs table: the output init loop continues
    -- without popping the value and the next lua_next misreads the stack
    return { [false] = true, type = "packet" }
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))
    file:write("started\n")
    file:close()
end

function log(args)
end

function deinit()
end
