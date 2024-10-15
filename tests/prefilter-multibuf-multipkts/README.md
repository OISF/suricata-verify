Test
====

Test that multibuffer is prefiltered the right way, even if occurences of buffers
are spanned over multiple packets, and the first try does not match.

https://redmine.openinfosecfoundation.org/issues/7326

PCAP
====

Pcap crafted with some http server and some python client that delays or not the writing of the headers
