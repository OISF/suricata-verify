function init (args)
    local needs = {}
    needs["http.request_headers"] = tostring(true)
    return needs
end

function match(args)
    SCFlowvarSet("key", 3, "value", 5)
    return 1
end
