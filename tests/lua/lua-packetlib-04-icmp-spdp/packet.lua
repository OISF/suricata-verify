local packet = require "suricata.packet"

function init (args)
    local needs = {}
    return needs
end

function match (args)
    p = packet.get()

    sp, err = p:sp()
    if err == nil then
        SCLogError("sp() should have failed for icmp")
        return 0
    end

    if err ~= "sp only available for tcp, udp and sctp" then
        SCLogError("sp() error message mismatch")
        return 0
    end

    return 1
end
