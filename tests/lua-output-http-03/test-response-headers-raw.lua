-- simple http match on response_headers_raw module
local packet = require "suricata.packet"
local http = require("suricata.http")

function init (args)
    local needs = {}
    needs["http.response_headers.raw"] = tostring(true)
    return needs
end

function match(args)
    local tx = http.get_tx()
    http_response_headers_raw, err = tx:response_headers_raw()

    if #http_response_headers_raw > 0 then
        if http_response_headers_raw:find("^Server: nginx/1.6.3") then
            return 1
        end
    end

    return 0
end
