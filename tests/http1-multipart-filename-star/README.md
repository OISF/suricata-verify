# HTTP/1 multipart `filename*` evades `file.name`

This test reproduces a filename-inspection differential in Suricata's HTTP/1
`multipart/form-data` parser.

The PCAP contains seven complete HTTP/1.1 flows. The important controls are:

- source port 41001: `filename="shell.php"`;
- source port 41003: `filename="safe.png"; filename*=UTF-8''shell.php`;
- source port 41004: `filename*=UTF-8''shell.php`.

Signature 1000000 confirms that Suricata parsed all seven POST requests.
Signature 1000001 inspects `file.name` for `shell.php`, while signature 1000002
does the same for `.htaccess`.

The ordinary dangerous filenames alert. The paired and `filename*`-only forms
are parsed as HTTP but produced no dangerous `file.name` alert. A downstream
Werkzeug parser selects `shell.php` or `.htaccess` from those same extended
parameters.

The PCAP was generated locally by `testing/suricata/generate_pcap.py`; it does
not contain traffic captured from an external system.

https://redmine.openinfosecfoundation.org/issues/9157
