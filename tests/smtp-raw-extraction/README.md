# SMTP raw extraction

This test verifies that the flag app-layers.protocols.smtp.raw-extraction set to
True will make suricata dump e-mails in raw form, including headers and e-mail
content.

The pcap file is downloaded from

```
https://osqa-ask.wireshark.org/questions/33094/extract-an-attachment-email-smtp-cap
```
