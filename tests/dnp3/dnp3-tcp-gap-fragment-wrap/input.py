"""input.pcap: see generate_wrap in ../dnp3-tcp-gap-request-tail/pcapgen.py."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'dnp3-tcp-gap-request-tail'))
import pcapgen
pcapgen.generate_wrap(os.path.join(HERE, 'input.pcap'))
