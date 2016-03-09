# How `http.server` works
## Classes hierarchy

    socketserver.BaseServer (most of functionality)
    -- socketserver.TCPServer
    ---- http.server.HTTPServer

    socketserver.BaseRequestHandler
    -- socketserver.StreamRequestHandler
    ---- http.server.BaseHTTPRequestHandler (HTTTP request parsing & interface for building responses)
    ------ http.server.SimpleHTTPRequestHandler (do_GET -- sending files and file lists over HTTP)

## Call sequence
* The server is initialized. It opens a socket and starts listening to it (`TCPServer.__init__`)
* `BaseServer.serve_forever()` is called. It starts an infinite loop, calling `BaseServer._handle_request_noblock()`
  * `BaseServer._handle_request_noblock()` calls `TCPServer.get_request()`, which accepts a connection(?) from the socket
  * Then `BaseServer.verify_request()` (always succeeds)
  * Then `BaseServer.process_request()` (or `BaseServer.handle_error()` in case of error)
    * `BaseServer.process_request()` calls `BaseServer.finish_request()`
      * `BaseServer.finish_request()` calls `BaseServer.RequestHandlerClass(request, client_address, self)` which is `BaseRequestHandler.__init__()`
        * `BaseRequestHandler.__init__()` calls `StreamRequestHandler.setup()`, then `BaseHTTPRequestHandler.handle()` and then `StreamRequestHandler.finish()`
          * `StreamRequestHandler.setup()` initializes `rfile` and `wfile`
          * `BaseHTTPRequestHandler.handle()` calls `BaseHTTPRequestHandler.handle_one_request()` until connection is closed
            * `BaseHTTPRequestHandler.handle_one_request()` reads the first line, sets `self.raw_requestline` and calls `BaseHTTPRequestHandler.parse_request()`
              * `BaseHTTPRequestHandler.parse_request()` parses the request line and sets `self.command`, `self.path` and `self.request_version`
              * `BaseHTTPRequestHandler.parse_request()` calls `http.client.parse_headers(self.rfile, _class=self.MessageClass)` to set `self.headers`
            * `BaseHTTPRequestHandler.handle_one_request()` then finds an appropriate `do_***()` method of itself and calls it
              * `SimpleHTTPRequestHandler`'s `.do_GET()` and `.do_HEAD()` both call `SimpleHTTPRequestHandler.send_head()`, which uses:
                * `BaseHTTPRequestHandler.send_response()`
                  * Which calls `BaseHTTPRequestHandler.log_request()`, which calls `BaseHTTPRequestHandler.log_message()`
                  * And then `BaseHTTPRequestHandler.send_response_only()`, which just appends appropriate protocol version, code and message to the headers buffer
                  * Finally, it sends `Server:` and `Date:` HTTP headers
                    * The former is from `BaseHTTPRequestHandler.version_string()` which is `self.server_version + ' ' + self.sys_version` -- `.sys_version` is `Python/*.*`
                * `BaseHTTPRequestHandler.send_header()` -- appends the header to the buffer and checks for `Connection:`
                * `BaseHTTPRequestHandler.end_headers()` -- appends `b"\r\n"` to the buffer and calls `BaseHTTPRequestHandler.flush_headers()`
                  * `BaseHTTPRequestHandler.flush_headers()` writes the buffer content to `wfile` and cleans it
                * Finally it may write some content to `wfile`
                * To send HTTP error response it calls `BaseHTTPRequestHandler.send_error(...)`
                  * `BaseHTTPRequestHandler.send_error(...)` calls `BaseHTTPRequestHandler.log_error(...)`
                    * `BaseHTTPRequestHandler.log_error(...)` just transfers its arguments to `BaseHTTPRequestHandler.log_message()`
                  * `BaseHTTPRequestHandler.send_error(...)` then writes appropriate response to `wfile`
            * `BaseHTTPRequestHandler.handle_one_request()` flushes `wfile`
            * In case of `socket.timeout` `BaseHTTPRequestHandler.handle_one_request()` calls `BaseHTTPRequestHandler.log_error("Request timed out")`
          * `StreamRequestHandler.finish()` flushes `wfile` and closes both streams
    * `BaseServer.process_request()` calls `TCPServer.shutdown_request()`, which calls `.shutdown(socket.SHUT_WR)` and (via `TCPServer.close_request()`) `.close()`
