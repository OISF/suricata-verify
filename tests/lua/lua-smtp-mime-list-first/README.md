Reproducer for lua/smtp: get_mime_list() starts its index at 1 and
passes it to the 0-based FFI accessor, so the first MIME header of the
part (Content-Type, which can carry the attachment name) is dropped.

The script requires Content-Type, Content-Transfer-Encoding and
Content-Disposition. tests/lua/lua-smtplib/test.lua pinned the buggy
two-field view and is updated to the fixed expectation.

Ticket: #9083.
