# Description

Test xor transform.

# PCAP

The pcap comes from running dummy HTTP1 server
and in parallel as client(s) :
```
curl 127.0.0.1:8080/get?data=%7Dk%BB%8Cze%BA%9B0y%BD%8Fhx%BB%9Anx%AD%8B
```

The uri was computed with script `./xor.py password=supersecret`
