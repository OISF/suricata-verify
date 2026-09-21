Reproducer for the lua tls lib reporting the wrong direction's
version in get_client_cert_info: client hello carries TLSv1, server
hello TLS 1.2; pre-fix both getters return TLS 1.2.
