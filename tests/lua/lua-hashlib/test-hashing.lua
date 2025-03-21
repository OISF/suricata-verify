local hashlib = require("suricata.hashlib")
local dns = require("suricata.dns")

local expected_sha256 = "080bdfdfcd8c2c7fce747f9be4603ced6253caac70894ad89d605309588c60f6"
local expected_sha1 = "00f495ffd50c8b5ef3645f61486dae496db0fe2e"
local expected_md5 = "27170ec0609347c6a158bb5b694822a5"

function init (args)
   local needs = {}
   return needs
end

local function tohex(str)
    local hex = {}
    for i = 1, #str do
        hex[i] = string.format("%02x", string.byte(str, i))
    end
    return table.concat(hex)
end

function test_sha256(name)
   -- Test one shot digest.
   hash = hashlib.sha256_digest(name)
   if tohex(hash) ~= expected_sha256 then
      return false
   end

   -- Test one shot hex digest.
   hash = hashlib.sha256_hexdigest(name)
   if hash ~= expected_sha256 then
      return false
   end

   -- Test hash with multiple updates.
   hasher = hashlib.sha256()
   hasher:update("www.")
   hasher:update("suricata-ids.")
   hasher:update("org")
   hash = hasher:finalize()
   if tohex(hash) ~= expected_sha256 then
      return false
   end

   -- Test hash with multiple updates and hex finalization.
   hasher = hashlib.sha256()
   hasher:update("www.")
   hasher:update("suricata-ids.")
   hasher:update("org")
   hash = hasher:finalize_to_hex()
   if hash ~= expected_sha256 then
      return false
   end

   return true
end

function test_sha1(name)
   -- Test one shot digest.
   hash = hashlib.sha1_digest(name)
   if tohex(hash) ~= expected_sha1 then
      return false
   end

   -- Test one shot hex digest.
   hash = hashlib.sha1_hexdigest(name)
   if hash ~= expected_sha1 then
      return false
   end

   -- Test hash with multiple updates.
   hasher = hashlib.sha1()
   hasher:update("www.")
   hasher:update("suricata-ids.")
   hasher:update("org")
   hash = hasher:finalize()
   if tohex(hash) ~= expected_sha1 then
      return false
   end

   -- Test hash with multiple updates and hex finalization.
   hasher = hashlib.sha1()
   hasher:update("www.")
   hasher:update("suricata-ids.")
   hasher:update("org")
   hash = hasher:finalize_to_hex()
   if hash ~= expected_sha1 then
      return false
   end

   return true
end

function test_md5(name)
   -- One shot digest.
   hash = hashlib.md5_digest(name)
   if tohex(hash) ~= expected_md5 then
      return false
   end

   -- One shot hex digest.
   hash = hashlib.md5_hexdigest(name)
   if hash ~= expected_md5 then
      return false
   end

   -- Test hash with multiple updates.
   hasher = hashlib.md5()
   hasher:update("www.")
   hasher:update("suricata-ids.")
   hasher:update("org")
   hash = hasher:finalize()
   if tohex(hash) ~= expected_md5 then
      return false
   end

   -- Test hash with multiple updates and hex finalization.
   hasher = hashlib.md5()
   hasher:update("www.")
   hasher:update("suricata-ids.")
   hasher:update("org")
   hash = hasher:finalize_to_hex()
   if hash ~= expected_md5 then
      return false
   end

   return true
end

function match(args)
   local tx = dns.get_tx()
   rrname = tx:rrname()

   if not test_sha256(rrname) then
      SCLogError("test_sha256 failed")
      return 0
   end

   if not test_sha1(rrname) then
      SCLogError("test_sha1 failed")
      return 0
   end

   if not test_md5(rrname) then
      SCLogError("test_md5 failed")
      return 0
   end

   return 1
end

