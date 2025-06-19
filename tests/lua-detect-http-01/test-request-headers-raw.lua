-- simple http match on request_headers_raw module
local packet = require "suricata.packet"
local http = require("suricata.http")

function init (args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    http_request_headers_raw, err = tx:request_headers_raw()

    if #http_request_headers_raw > 0 then
        if http_request_headers_raw:find("User%-Agent: curl") then
            return 1
        end
    end

    return 0
end
