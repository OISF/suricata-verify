local filelib = require("suricata.file")
local config = require("suricata.config")
local results
local names

function init(args)
   local needs = {}
   needs["type"] = "file"
   return needs
end

function setup(args)
   results = assert(io.open(config.log_path() .. "/results.log", "w"))
   names = {}
end

function log(args)
   -- One flow, a file in each direction, both truncated, pcap ends
   -- without FINs: the file loggers run from the end-of-pcap pseudo
   -- passes (a toserver pseudo for the ts stream, a toclient pseudo
   -- for the tc stream, the latter the eof one). The file handle must
   -- anchor the logger's dir (the file container's direction) so each
   -- file resolves against its own container.
   local f = filelib.get_file()
   if f == nil then
      results:write("no-file\n")
      return
   end
   local ok, name = pcall(function() return f:name() end)
   if not ok then
      results:write(string.format("name-err %s\n", tostring(name)))
      return
   end
   if name == nil then
      results:write("name=nil\n")
      return
   end
   table.insert(names, name)
   results:write(string.format("name=%s\n", name))
end

function deinit()
   if results then
      -- both files of the transaction must have resolved to their own
      -- container
      if #names == 2 then
         table.sort(names)
         results:write(string.format("both %s %s\n", names[1], names[2]))
      end
      results:close()
   end
end
