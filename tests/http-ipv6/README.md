# Description

Test http over IPv6

# PCAP

The pcap comes from running
`python -m SimpleHTTPServer 8000` or `python3 -m http.server` as a server  and the following command
`curl "[::1]:8000/"` as a client
