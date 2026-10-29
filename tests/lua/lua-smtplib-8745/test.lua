local smtplib = require("suricata.smtp")

function init ()
    return {}
end

function match ()
    local tx = assert(smtplib.get_tx())
    local fields = tx:get_mime_list()
    -- The first header was omitted before the #9083 fix in 8.0.8.
    -- Allow both counts: this test checks that enumeration terminates.
    assert(#fields <= 2)
    return 1
end
