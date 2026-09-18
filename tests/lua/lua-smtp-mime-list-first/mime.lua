local smtp = require("suricata.smtp")

function init(args)
    return {}
end

function match(args)
    local tx = smtp.get_tx()
    if tx == nil then
        return 0
    end
    local fields = tx:get_mime_list()
    if fields[1] ~= "Content-Type" then
        return 0
    end
    if fields[2] ~= "Content-Transfer-Encoding" then
        return 0
    end
    if fields[3] ~= "Content-Disposition" then
        return 0
    end
    if #fields ~= 3 then
        return 0
    end
    return 1
end
