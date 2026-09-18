local smtp = require("suricata.smtp")
local config = require("suricata.config")

function init(args)
    local needs = {}
    needs["protocol"] = "smtp"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))
end

function log(args)
    local tx = smtp.get_tx()
    local from = "nil"
    if tx ~= nil then
        from = tostring(tx:get_mail_from())
    end
    file:write("tx=" .. tostring(args and args["tx_id"]) .. " from=" .. from .. "\n")
    file:flush()
end

function deinit()
    file:close()
end
