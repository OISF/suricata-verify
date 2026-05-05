local ntp = require("suricata.ntp")
local config = require("suricata.config")
local logger = require("suricata.log")

local filename = "lua-ntp.log"

local function to_hex(bytes)
   local parts = {}
   for i = 1, #bytes do
      parts[#parts + 1] = string.format("%02x", string.byte(bytes, i))
   end
   return table.concat(parts, ":")
end

function init(args)
   local needs = {}
   needs["protocol"] = "ntp"
   return needs
end

function setup(args)
   logger.notice("lua: setup()")
   file = assert(io.open(config.log_path() .. "/" .. filename, "w"))
end

function log(args)
   local tx, err = ntp.get_tx()
   if tx == nil then
      print(err)
      return
   end

   local msg = string.format("NTP version=%d mode=%d stratum=%d reference_id=%s",
      tx:version(), tx:mode(), tx:stratum(), to_hex(tx:reference_id()))
   write(msg)
end

function deinit(args)
   file:close(file)
end

function write(msg)
   file:write(msg .. "\n")
end
