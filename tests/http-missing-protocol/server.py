#!/usr/bin/env python

import http.server
import socketserver
import logging

PORT = 8000

class GetHandler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        logging.error(self.headers)
        self.send_response(200, 'OK')
        self.send_header('Content-type', 'txt')
        self.end_headers()
        self.wfile.write(bytes(self.headers))


Handler = GetHandler
httpd = socketserver.TCPServer(("", PORT), Handler)

httpd.serve_forever()
