-- an init() table with a number key: the loader must skip it, not hand
-- the converted key back to lua_next
function init(args)
    return { false }
end

function match(args)
    return 1
end
