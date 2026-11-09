calls = 0

function init(args)
    return {}
end

function match(args)
    calls = calls + 1
    if calls == 1 then
        -- exceeds security.lua.max-bytes: sets memory_limit_error
        local s = string.rep("M", 400000)
        return 1
    end
    error("generic failure")
end
