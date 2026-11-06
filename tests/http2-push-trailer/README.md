HTTP/2 response with a PUSH_PROMISE issued while the body is in flight, its header
block finished by a CONTINUATION on the parent stream, and a genuine trailer block
split over HEADERS plus CONTINUATION closing the stream. A CONTINUATION takes its
classification from the block it continues, so the promised fields must not reach
http.trailer while the real trailer block must. A second stream reverses the order:
the PUSH_PROMISE is issued before the response, so the CONTINUATION that finishes it
carries a :status while no response header section has been seen yet. Arming the
header section on such a frame makes the response behind it read as trailers and hides
it from http.response_header. Regenerate with python3 make-pcap.py.
