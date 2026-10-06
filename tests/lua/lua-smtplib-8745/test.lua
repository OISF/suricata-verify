local smtplib = require("suricata.smtp")

function init ()
    return {}
end

function match ()
    local tx = assert(smtplib.get_tx())
    local fields = tx:get_mime_list()
    assert(#fields < 2)
    return 1
end
