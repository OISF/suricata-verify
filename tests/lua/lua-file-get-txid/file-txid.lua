local filelib = require("suricata.file")
local config = require("suricata.config")
local results

function init(args)
   local needs = {}
   needs["type"] = "file"
   return needs
end

function setup(args)
   results = assert(io.open(config.log_path() .. "/results.log", "w"))
end

function log(args)
   -- The file log callback sets the tx registry entry (the file's
   -- transaction) before log() runs, so file:tx_id() must return the tx
   -- id of the file's transaction, not a "no tx available" error.
   local f = filelib.get_file()
   if f == nil then
      results:write("no-file\n")
      return
   end
   local ok, txid = pcall(function() return f:tx_id() end)
   if not ok then
      results:write(string.format("txid-err %s\n", tostring(txid)))
      return
   end
   results:write(string.format("txid=%d name=%s\n", txid, tostring(f:name())))
end

function deinit()
   if results then
      results:close()
   end
end
