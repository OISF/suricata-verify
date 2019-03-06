# Description

Test http unrecognized authorisation method

# PCAP

The pcap comes from running
`python -m SimpleHTTPServer 8000` or `python3 -m http.server` as a server  and the following command
`curl --header "Authorization: Turbo customAuthDataHere" 127.0.0.1:8000/` as a client
