local packet = require "suricata.packet"
local logger = require("suricata.log")

function init (args)
    local needs = {}
    return needs
end

function match (args)
    p = packet.get()
    payload = p:payload()
    ts = p:timestring_iso8601()

    for line in payload:gmatch("([^\r\n]*)[\r\n]+") do
        if line == "GET /index.html HTTP/1.0" then
            ipver, srcip, dstip, proto, sp, dp = p:tuple()
            logger.notice(string.format("%s %s->%s %d->%d (pcap_cnt:%d) match! %s", ts, srcip, dstip, sp, dp, p:pcap_cnt(), line));
            return 1
        end
    end

    return 0
end
