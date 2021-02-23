import sys

# write header
sys.stdout.buffer.write(b"FPC\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
for i in range(32):
    # ethernet layer with mpls following
    sys.stdout.buffer.write(b"\x01\x02\x03\x04\x05\x06\x01\x02\x03\x04\x05\x07\x88\x47")
    # mpls layer with ethernet following
    sys.stdout.buffer.write(b"\x00\x01\x01\x00\x00\x00\x00\x00")
# write footer
sys.stdout.buffer.write(b"FPC0")
