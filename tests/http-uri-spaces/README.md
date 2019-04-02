# Description

Test http URI detection with spaces in it

# PCAP

The pcap comes from the idea in
https://redmine.openinfosecfoundation.org/issues/2881
You can reproduce a similar behavior with running a server and curl against it
`python3 -m http.server`
`curl "127.0.0.1:8000/uri afterspace"`
