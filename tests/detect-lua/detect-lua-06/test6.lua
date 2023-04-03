function init (args)
    local needs = {}
    needs["http.request_headers"] = tostring(true)
    needs["flowint"] = {"cnt"}
    return needs
    end

function match(args)
    print "inspecting"
    a = ScFlowintGet(0)
    if a == nil then
        print "new var set to 2"
        ScFlowintSet(0, 2)
    end
    a = ScFlowintDecr(0)
    if a == 0 then
        print "match"
        return 1
    end
    return 0
end
return 0
