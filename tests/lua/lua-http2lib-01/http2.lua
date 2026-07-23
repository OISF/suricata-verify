-- simple http match on request_headers_raw module
local http = require("suricata.http")

function init (args)
    return {}
end

function match(args)
    local tx = http.get_tx()
    uriraw, err = tx:request_uri_raw()

    if #uriraw > 0 then
        if uriraw:find("/toto") then
            return 1
        end
    end

    return 0
end
