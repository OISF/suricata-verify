-- simple fast-log to file lua module
local packet = require "suricata.packet"
local smtp = require "suricata.smtp"
local logger = require("suricata.log")

name = "smtp_lua.log"

function init (args)
    local needs = {}
    needs["protocol"] = "smtp"
    return needs
end

function setup (args)
    filename = SCLogPath() .. "/" .. name
    file = assert(io.open(filename, "a"))
    logger.info("Log Filename " .. filename)
    count = 0
end

function log(args)
   p = packet.get()
   ts = p:timestring_legacy()
   local smtptx = smtp.get_tx()
   local from = smtptx:get_mail_from()
   local to = smtptx:get_rcpt_list()
   to_string = ""
   for key,val in pairs(to) do
      to_string = to_string .. val
   end
   file:write(ts .. " FROM " .. from .. " TO {" .. to_string .. "}\n")
   file:flush()

   count = count + 1
end

function deinit (args)
    logger.info ("transactions logged: " .. count);
    file:close(file)
end
