-- simple http match on response_body module
local http = require("suricata.http")

function init (args)
    local needs = {}
    needs["http.response_body"] = tostring(true)
    return needs
end

function match(args)
    local tx, err = http.get_tx()
    http_response_body, err = tx:response_body()
    if http_response_body ~= nil then
        for i = 1,#http_response_body,1
        do
            if http_response_body[i]:find("^SGVsbG8gV29ybGQu") then
                return 1
            end
        end
    end

    return 0
end
