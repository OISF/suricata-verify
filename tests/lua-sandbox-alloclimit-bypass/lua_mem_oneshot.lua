function init(args)
    local needs = {}
    needs["payload"] = tostring(true)
    return needs
end

function match(args)
    -- Allocates 400KB via a single new-allocation (ptr==NULL path).
    -- With correct enforcement, alloc_limit blocks this and the script
    -- fails with "memory limit exceeded" -- no alert fires.
    -- On affected versions (7.0.15, 8.0.4), the script runs successfully
    -- and fires an alert because ptr==NULL bypasses the alloc_limit check.
    local s = string.rep("B", 400000)
    return 1
end
