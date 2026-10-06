# Description

Test json_decode transform
https://redmine.openinfosecfoundation.org/issues/8128

# PCAP

The pcap comes from running
 `curl --header "Content-Type: application/json"   --request POST   --data @data.json http://localhost:8080/api`
against a HTTP server run by server.go
