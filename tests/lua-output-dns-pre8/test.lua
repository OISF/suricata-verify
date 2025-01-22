filename = "lua-dns.log"

function init (args)
   local needs = {}
   needs["protocol"] = "dns"
   return needs
end

function setup (args)
   SCLogNotice("lua: setup()")
   file = assert(io.open(SCLogPath() .. "/" .. filename, "w"))
end

function log(args)
   ts = SCPacketTimeString()
   ip_ver, src_ip, dst_ip, proto, sp, dp = SCFlowTuple()
   tx_id = DnsGetTxid()

   queries = DnsGetQueries()
   if queries ~= nil then
      for n, t in pairs(queries) do
	 msg = string.format(
	    "%s [**] Query TX %04x [**] %s [**] %s [**] %s:%d -> %s:%d",
	    ts,
	    tx_id,
	    t["rrname"],
	    t["type"],
	    src_ip,
	    sp,
	    dst_ip,
	    dp)
	 write(msg)
      end
   end

   rcode = DnsGetRcode()
   if rcode ~= nil then
      msg = string.format(
	 "%s [**] Response TX %04x [**] %s [**] %s:%d -> %s:%d",
	 ts,
	 tx_id,
	 rcode,
	 src_ip,
	 sp,
	 dst_ip,
	 dp)
      write(msg)
   end
   
   answers = DnsGetAnswers()
   if answers ~= nil then
      for n, t in pairs(answers) do
	 msg = string.format(
	    "%s [**] Response TX %04x [**] %s [**] %s [**] TTL %d [**] %s [**] %s:%d -> %s:%d",
	    ts,
	    tx_id,
	    t["rrname"],
	    t["type"],
	    t["ttl"],
	    t["addr"],
	    src_ip,
	    sp,
	    dst_ip,
	    dp);
	 write(msg)
      end
   end
   
   authorities = DnsGetAuthorities()
   if authorities ~= nil then
      for n, t in pairs(authorities) do
	 msg = string.format(
	    "%s [**] Response TX %04x [**] %s [**] %s [**] TTL %d [**] %s:%d -> %s:%d",
	    ts,
	    tx_id,
	    t["rrname"],
	    t["type"],
	    t["ttl"],
	    src_ip,
	    sp,
	    dst_ip,
	    dp);
	 write(msg)
      end
   end
   
end

function deinit(args)
   file:close(file)
end

function write(msg)
   file:write(msg .. "\n")
end
