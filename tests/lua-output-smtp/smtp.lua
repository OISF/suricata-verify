local io = require("io")
-- simple fast-log to file lua module
name = "smtp_lua.log"

function init (args)
    local needs = {}
    needs["protocol"] = "smtp"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    SCLogInfo("Log Filename " .. filename)
    count = 0
end

function log(args)
   ts = SCPacketTimeString()
   from = SMTPGetMailFrom()
   to = SMTPGetRcptList()
   to_string = ""
   for key,val in pairs(to) do
      to_string = to_string .. val
   end
   file:write(ts .. " FROM " .. from .. " TO {" .. to_string .. "}\n")
   file:flush()

   count = count + 1
end

function deinit (args)
    SCLogInfo ("transactions logged: " .. count);
    file:close(file)
end
