# Description

Test zlib_deflate transform
https://redmine.openinfosecfoundation.org/issues/7846

# PCAP

The pcap comes from running
 `curl -i -v "http://127.0.0.1:8080/gzb64?value=eJwLycgsVgCi5PzcgqLU4uLUFIWSjNQ8haTE4lQzE93UvOT8lNQULgAeFA3n"`
against a HTTP server
The value was computed with `echo "This is compressed then base64-encoded" | openssl zlib | base64`
