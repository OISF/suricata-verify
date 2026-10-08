local config = require("suricata.config")

-- an array entry next to a valid option: the number key must be skipped
function init(args)
    return { true, type = "packet" }
end

function setup(args)
    n = 0
end

function log(args)
    n = n + 1
end

function deinit(args)
    local f = assert(io.open(config.log_path() .. "/results.log", "w"))
    f:write("logged " .. tostring(n > 0) .. "\n")
    f:close()
end
