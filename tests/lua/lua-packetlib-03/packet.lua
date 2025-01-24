local packet = require "suricata.packet"

function init (args)
    local needs = {}
    return needs
end

function match (args)
    p = packet.get()
    if p:sp() == 6666 and p:dp() == 63 then
        ts = p:timestring_iso8601()

        SCLogNotice(string.format("%s %d->%d (pcap_cnt:%d) match!", ts, p:sp(), p:dp(), p:pcap_cnt()));
        return 1
    end

    return 0
end
