local ssh = require("suricata.ssh")
local ja3 = require("suricata.ja3")

function init(args)
    return {}
end

function match(args)
    if ssh.enable_hassh() ~= nil then
        return 0
    end
    if ja3.enable_ja3() ~= nil then
        return 0
    end
    return 1
end
