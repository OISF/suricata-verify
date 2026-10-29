set pagination off
set confirm off
break FileOpenFileWithId
commands
    silent
    printf "SV_FAULT_INJECTION: FileOpenFileWithId -> -1\n"
    return (int)-1
    continue
end
run
