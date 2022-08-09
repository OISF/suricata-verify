Description
-----------
Since the feature for extracting MIME urls (ref: [Feature #2054](https://redmine.openinfosecfoundation.org/issues/2054))
was introduced, the logging of urls in case the `suricata.yaml` configuration was not updated
has been broken (ref: [Bug #5174](https://redmine.openinfosecfoundation.org/issues/5174)).
The issue happens when both the `extract-urls-schemes` and `log-url-scheme` settings are
missing from `suricata.yaml`.
The behavior in such a case should be fallback to the defaults i.e. only extract the urls
that begin with the `http` scheme.

PCAP
----
PCAP comes from the existing test [smtp-extract-url-schemes](https://github.com/OISF/suricata-verify/blob/master/tests/smtp-extract-url-schemes).

Reported and fixed by
---------------------
Eric Leblond <el@stamus-networks.com>
