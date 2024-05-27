global_data = {}

function init(args)
   for i = 1, 8000 do
      global_data[i] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   end

   return {}
end

function match(args)
   local data = {}
   for i = 1, 17000 do
      data[i] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
   end
end
