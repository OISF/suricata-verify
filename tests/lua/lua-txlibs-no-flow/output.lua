local config = require("suricata.config")

function init(args)
    local needs = {}
    needs["type"] = "packet"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))

    -- setup() runs without a flow/tx. ja3.get_tx() must report the
    -- protocol/flow problem, not treat the NeedProto "no flow" error as a
    -- TLS match and then fail on the (absent) tx.
    local ja3 = require("suricata.ja3")
    local ok, r1, r2 = pcall(ja3.get_tx)
    local msg = tostring(r1) .. " " .. tostring(r2)
    if ok and r2 ~= nil and string.find(msg, "protocol") then
        file:write("OK\n")
    else
        file:write("BAD " .. msg .. "\n")
    end
    file:close()
end

function log(args)
end

function deinit()
end
