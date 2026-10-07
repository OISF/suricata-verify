-- Read the sender through a handle obtained from the transaction that is
-- current right now: this has to keep working, on either side of the fix.
local smtp = require("suricata.smtp")

seen = false

function init (args)
    return { packet = true }
end

function match (args)
    if seen == true then
        return 0
    end
    local tx = smtp.get_tx()
    if tx == nil then
        return 0
    end
    local from = tx:get_mail_from()
    if type(from) == "string" and #from > 0 then
        seen = true
        return 1
    end
    return 0
end
