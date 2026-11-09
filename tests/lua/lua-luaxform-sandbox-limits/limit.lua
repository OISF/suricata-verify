-- allocate far beyond the configured max-bytes: the sandbox allocator
-- refuses, the transform fails and the buffer keeps the untransformed
-- data
function transform(input, args)
    local big = string.rep("a", 1000000)
    return big, #big
end
