function init(args)
   local requires = {}
   return requires
end

function match(args)
   pcall(function() error("error") end)
   return 1
end
