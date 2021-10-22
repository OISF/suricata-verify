import sys
import binascii
import urllib

key = binascii.unhexlify("0d0ac8ff")
xored = ""
for i in range(len(sys.argv[1])):
    xored = xored + chr(ord(sys.argv[1][i]) ^ ord(key[i%len(key)]))
print(urllib.quote_plus(xored))
