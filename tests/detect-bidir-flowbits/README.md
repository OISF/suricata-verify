# Description

Test bidirection matching with a real life example
https://redmine.openinfosecfoundation.org/issues/5665

# PCAP

Crafted from the rules
Client is
`curl -d '"goog:chromeOptions";"binary";"args":["' -X POST 127.0.0.1:8080/wd/hub/session`
Server is server.go
