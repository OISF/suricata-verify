-- simple http match on request_line module
local http = require("suricata.http")

function init (args)
    local needs = {}
    needs["http.request_line"] = tostring(true)
    return needs
end

function match(args)
    local tx, err = http.get_tx()
    http_request_line, err = tx:request_line()

    if #http_request_line > 0 then
        --GET /base64-hello-world.txt HTTP/1.1
        if http_request_line:find("^GET") then
            return 1
        end
    end

    return 0
end
