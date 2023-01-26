function init (args)
    local needs = {}
    needs["http.request_headers"] = tostring(true)
    needs["flowvar"] = {"cnt"}
    return needs
    end

function match(args)
    a = ScFlowvarGet(0)
    if a then
        a = tostring(tonumber(a)+1)
        print (a)
        ScFlowvarSet(0, a, #a)
    else
        a = tostring(1)
        print (a)
        ScFlowvarSet(0, a, #a)
    end

    print ("pre check: " .. (a))
    if tonumber(a) == 2 then
        print "match"
        return 1
    end
    return 0
end
return 0
