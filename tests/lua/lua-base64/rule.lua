local base64 = require("suricata.base64")
local dns = require("suricata.dns")

local rrname = "www.suricata-ids.org"
local expected_base64 = "d3d3LnN1cmljYXRhLWlkcy5vcmc="
local expected_base64_nopad = "d3d3LnN1cmljYXRhLWlkcy5vcmc"

local input_base64_with_spaces = "d3 d3 Ln N1 cm lj YX Rh LW lk cy 5v cm c="

function init (args)
   local needs = {}
   needs["dns.request"] = true
   return needs
end

function match(args)
   local tx = dns.get_tx()
   local rrname = tx:rrname()

   encoded = base64.encode(rrname)
   if encoded ~= expected_base64 then
      print("base64.encode failed")
      return 0
   end

   decoded = base64.decode(encoded)
   if decoded ~= rrname then
      print("base64.decode failed")
      return 0
   end

   decoded = base64.decode_padopt(encoded)
   if decoded ~= rrname then
      print("base64.decode failed")
      return 0
   end

   encoded = base64.encode_nopad(rrname)
   if encoded ~= expected_base64_nopad then
      print("base64.encode_nopad failed")
      return 0
   end

   decoded = base64.decode_nopad(encoded)
   if decoded ~= rrname then
      print("base64.decode failed")
      return 0
   end

   decoded = base64.decode_padopt(encoded)
   if decoded ~= rrname then
      print("base64.decode failed")
      return 0
   end

   -- RFC 2045 allows spaces.
   decoded = base64.decode_rfc2045(input_base64_with_spaces)
   if decoded ~= rrname then
      print("base64.decode_rfc2045 failed")
      return 0
   end

   -- RFC 4648 does not allow spaces
   decoded = base64.decode_rfc4648(input_base64_with_spaces)
   if decoded ~= "w" then
      print("base64.decode_rfc2045 failed")
      return 0
   end

   return 1
end

