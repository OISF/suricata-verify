local config = require("suricata.config")
local dns = require("suricata.dns")

local filename = "lua-dns.log"
local file

function init(args)
   return { protocol = "dns" }
end

function setup(args)
   file = assert(io.open(config.log_path() .. "/" .. filename, "w"))
end

function log(args)
   local tx = dns.get_tx()
   local answers = tx:answers()

   for _, answer in pairs(answers) do
      if answer["type"] == "OPT" then
         file:write(answer["addr"] .. "\n")
         file:flush()
      end
   end
end

function deinit(args)
   file:close()
end
