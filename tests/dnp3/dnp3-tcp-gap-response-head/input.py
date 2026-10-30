"""input.pcap: two long-lived dnp3 connections, 20 marked requests each, every frame in two
TCP segments; the first half of response 6 on the 10.128.0.0 connection is missing, so the data after the gap starts in the middle of a frame. Uses pcapgen.py in dnp3-tcp-gap-request-tail.
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'dnp3-tcp-gap-request-tail'))
import pcapgen
OUT = os.path.join(HERE, 'input.pcap')
pcapgen.generate(OUT, 'dnp3', 'head', conns=2, transactions=40, lost_request=5, direction='response')
