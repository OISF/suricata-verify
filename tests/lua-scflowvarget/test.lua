local io = require("io")
function init (args)
    local needs = {}
    needs["http.request_headers"] = tostring(true)
    needs["flowvar"] = {"TestVar"}
    return needs
end

function match(args)
    print "Before loading Variable"
    testVar = ScFlowvarGet(0);
    if testVar then
      print "testVar is set"
    else
      print "testVar is not set"
      return 0
    end
    return 1
end
