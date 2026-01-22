# Description

Test gunzip transform
https://redmine.openinfosecfoundation.org/issues/7846

# PCAP

The pcap comes from running
 `curl -i -v "http://127.0.0.1:8080/gzb64?value=H4sIADfTcWkAAwvJyCxWAKLk/NyCotTi4tQUhZKM1DyFpMTiVDMT3dS85PyU1BQuAFtmgsgnAAAA"`
against a HTTP server
The value was computed with `echo "This is compressed then base64-encoded" | gzip | base64`
