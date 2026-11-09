function init(args)
    -- boolean key: lua_tostring returns NULL and the value is left on the
    -- stack, so the next lua_next reads the wrong slot
    return { [false] = true }
end

function match(args)
    return 1
end
