local smtplib = require("suricata.smtp")

function init ()
    return {}
end

function match ()
    local tx = assert(smtplib.get_tx())
    assert(tx:get_mail_from() == "int@smtp.lab.com")
    local rcpts = tx:get_rcpt_list()
    assert(rcpts[1] == "test@gw.com")

    local fields = tx:get_mime_list()
    assert(#fields == 2)
    assert(fields[1] == "Content-Transfer-Encoding")
    assert(fields[2] == "Content-Disposition")
    assert(tx:get_mime_field(fields[1]) == "base64")
    assert(tx:get_mime_field(fields[2]) == "attachment;filename*0=smtptest-2021-02-25T13-54-22Z-aefb2fc1308d62f4b6c74769f69b13;filename*1=ddf80e995fd98ae442f3be499ea928c67f..zip")

    return 1
end
