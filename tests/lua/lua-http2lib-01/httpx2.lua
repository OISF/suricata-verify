-- simple http or http2 match on request_uri_raw
local http = require("suricata.http")

function init (args)
   local needs = {}
   needs["http.uri"] = true
   return needs
end

function match(args)
    local tx = http.get_h2_tx()
    uriraw, err = tx:request_uri_raw()

    if #uriraw > 0 then
        if uriraw:find("/toto") then
            return 1
        end
    end

    return 0
end
