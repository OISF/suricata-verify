function init()
end

local function get_value(item, key)
   if string.find(item, key) then
	   local _, value = string.match(item, "(%a+)%s*(%d*)")
	   if value ~= "" then
		   return tonumber(value)
	   end
   end

   return nil
end

-- Arguments supported
local bytes_key = "bytes"
local offset_key = "offset"
function transform(input_len, input, argc, args)
   local bytes = input_len
   local offset = 0

   -- Look for optional bytes and offset arguments
   for i, item in ipairs(args) do
	   local value = get_value(item, bytes_key)
	   if value ~= nil then
		   bytes = value
	   else
		   value = get_value(item, offset_key)
		   if value ~= nil then
			   offset = value
		   end
	   end
   end

   local str_len = #input
   if offset < 0 or offset > str_len then
	   print("offset is out of bounds: " .. offset)
	   return nil
   end

   local avail_len = str_len - offset
   if bytes < 0 or bytes > avail_len then
       print("invalid bytes " ..  bytes .. " or bytes exceeds available  length " .. avail_len)
	   return nil
   end

   local sub = string.sub(input, offset + 1, offset + bytes)
   return string.upper(sub), bytes
end
