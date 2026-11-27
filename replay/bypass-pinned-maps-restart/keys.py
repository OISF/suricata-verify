# print the sorted keys of a bpftool JSON map dump, one per line
import json, sys
for k in sorted(" ".join(e["key"]) for e in json.load(open(sys.argv[1]))):
    print(k)
