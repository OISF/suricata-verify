# Description

Test HTTP protocol detection against evil server pretending first to be FTP

# PCAP

The pcap is inspired by running
`python server.py` as a server  and the following command
`curl 127.0.0.1:8080` as a client

But, it was modified so as to have the server speak faster than the client for the first TCP payload data.
