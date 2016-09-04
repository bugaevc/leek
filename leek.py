#! /usr/bin/python3
import sys
import os
import pathlib
import urllib.parse
import html
import io
import time
import calendar
import json
import threading
import webbrowser
import ipaddress

from socketserver import ThreadingMixIn
from http.server import (BaseHTTPRequestHandler,
                         SimpleHTTPRequestHandler, HTTPServer)


class RangeFilePseudoPath:
    def __init__(self, path, start, end):
        self.path = path
        self.start = start
        self.end = end
    def open(self, *args, **kwargs):
        f = self.path.open(*args, **kwargs)
        f.seek(self.start, 0)
        return RangeFileReader(f, self.start, self.end)

class RangeFileReader:
    def __init__(self, f, start, end):
        self.f = f
        self.start = self.pos = start
        self.end = end
    def close(self):
        self.f.close()
    def read(self, ln=None):
        assert self.start <= self.pos <= self.end
        if ln is None:
            ln = self.end - self.pos
        to_read = max(min(ln, self.end - self.pos), 0)
        res = self.f.read(to_read)
        assert len(res) == to_read
        self.pos += to_read
        return res

class ListDirFormatter:

    template = None # To be loaded

    def __init__(self, folder):
        self.folder = folder
        self.buffer = []

    def add_line(self, **kwargs):
        self.buffer.append(self.template['item'].format(
            icon_class=self.get_icon_class(kwargs['type'], kwargs['ext']),
            **kwargs))

    def get_text(self):
        return self.template['main'].format(
            folder=self.folder,
            css=self.template['css'],
            content='\n'.join(self.buffer)
            )

    def get_icon_class(self, ctype, ext):
        if ctype == 'folder':
            res = 'folder'
        elif ctype == 'parent folder':
            return 'fa-level-up'
        else:
            c1, c2 = ctype.split('/')
            if c1 in ['audio', 'image', 'text', 'video']:
                res = 'file-{}'.format(c1)
            else:
                res = 'file'
            def check_for(*types):
                return any(any(t in s for s in (c1, c2, ext)) for t in types)
            if check_for('zip', 'rar', 'tar', 'gz', '7z'):
                res = 'file-archive'
            elif check_for('pdf'):
                res = 'file-pdf'
            elif check_for('word', 'doc'):
                res = 'file-word'
            elif check_for('excel', 'xls'):
                res = 'file-excel'
            elif check_for('powerpoint', 'ppt'):
                res = 'file-powerpoint'
            elif check_for('js', 'script', 'xml', 'css', 'html'):
                res = 'file-code'
        return 'fa-{}-o'.format(res)


class LeekServer(ThreadingMixIn, HTTPServer):

    daemon_threads = True

    def handle_error(self, request, client_adress):
        from traceback import format_exception_only, print_exc
        import socket
        p = sys.exc_info()[:2]
        if isinstance(p[1], ConnectionResetError):
            print(client_adress[0], client_adress[1],
                  '- ConnectionResetError')
            return
        print('Exception happened during processing of request from',
              client_adress)
        if isinstance(p[1], socket.error):
            print(*format_exception_only(*p), sep='', end='')
        else:
            print('-' * 40)
            print_exc(file=sys.stdout)
            print('-' * 40)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.events_feed = [threading.Event(), None, None, None]
        self.events_lock = threading.Lock()
        self.request_cnt = 0

    def fire_event(self, event_type, data):
        with self.events_lock:
            next_event = [threading.Event(), None, None, None]
            self.events_feed[1:] = event_type, data, next_event
            self.events_feed[0].set()
            self.events_feed = next_event

class LeekRequestHandler(SimpleHTTPRequestHandler):

    server_version = "Leek/0.3"
    protocol_version = "HTTP/1.1"

    def send_head(self):
        """Send the response headers.

        Return a file-like object representing response body or None.

        """
        path = self.find_the_file(self.path)
        if not isinstance(path, pathlib.Path):
            return path

        f = self.handle_headers(path)
        if f is None:
            return None
        return f.open('rb')

    def find_the_file(self, path):
        """Decide which local file or folder corresponds to the requested URI.

        Send 301 or 404 where appropriate.
        Return either pathlib.Path (the file was found),
        None (nothing further to do) or a file-like object (directory listing).

        """
        path = pathlib.Path(self.translate_path(path))
        if path.is_dir():
            # addressing scheme, network location, path, query, fragment identifier
            parts = urllib.parse.urlsplit(self.path)
            if not parts[2].endswith('/'):
                self.send_response(301)
                parts = list(parts)
                parts[2] += '/'
                self.send_header("Location", urllib.parse.urlunsplit(parts))
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = path / index
                if index.exists():
                    path = index
                    break
            else:
                return self.list_directory(path)
        if not path.exists():
            self.send_error(404, "File not found")
            return None
        return path

    def handle_headers(self, f):
        """Handle some request headers and send appropriate response headers.

        Return None or an object with .open() method.

        """
        IF_MD_SINCE = 'If-Modified-Since'
        IF_UNMD_SINCE = 'If-Unmodified-Since'
        IF_RANGE = 'If-Range'
        RANGE = 'Range'

        fs = f.stat()
        length = fs.st_size
        last_modified = int(fs.st_mtime)
        ctype = self.guess_type(str(f))

        try:
            if IF_MD_SINCE in self.headers:
                stamp = self.parse_time(self.headers[IF_MD_SINCE])
                if last_modified == stamp:
                    self.send_response(304) # Not modified
                    return None
            if IF_UNMD_SINCE in self.headers:
                stamp = self.parse_time(self.headers[IF_UNMD_SINCE])
                if last_modified > stamp:
                    self.send_error(412) # Modified - Precondition Failed
                    return None

            use_range = False
            if RANGE in self.headers:
                use_range = True
                if IF_RANGE in self.headers:
                    if self.parse_time(self.headers[IF_RANGE]) != last_modified:
                        use_range = False

            if use_range:
                start, end = self.headers[RANGE][len('bytes='):].split('-')
                tmp = self.handle_byte_range(f, length, start, end)
                if tmp is None:
                    return None
                f, length = tmp
            else:
                self.send_response(200)
            self.send_header("Content-Length", str(length))
            self.send_header("Content-Type", ctype)
            return f
        finally:
            self.send_header("Last-Modified",
                                     self.date_time_string(last_modified))
            self.send_header("Accept-Ranges", 'bytes')
            self.end_headers()

    def handle_byte_range(self, f, length, start=None, end=None):
        """Create a file-like object for reading a byte-range of f.

        length is the total length of f.
        start and end are treated exactly as in HTTP 'Range' header.
        Send response line and 'Content-Range' header.
        Return None or a tuple of an object with .open() method and
        the length of its content.

        """
        try:
            start = int(start) if start else None
            end = int(end) if end else None
        except ValueError:
            self.send_error(400)
            return None
        if start is not None:
            if end is None:
                end = length - 1
            if start >= length:
                self.send_error(416)
                return None
            if start > end:
                self.send_response(200)
                return f, length
        else:
            if end <= 0:
                self.send_error(416)
                return None
            start = max(length - end, 0)
            end = length - 1
        self.send_response(206)
        self.send_header("Content-Range",
                         "bytes {}-{}/{}".format(start, end, length))
        return RangeFilePseudoPath(f, start, end + 1), end - start + 1


    def list_directory(self, path):
        """List directory contents.

        Return either None or a file-like object.

        """
        try:
            files = sorted(path.iterdir(),
                           key=lambda p: (not p.is_dir(), p.name))
        except PermissionError:
            self.send_error(403, "No permission to list directory")
            return None
        displaypath = html.escape(urllib.parse.unquote(self.path))
        r = ListDirFormatter(displaypath)
        r.add_line(
                link='../',
                name='..',
                ext='/',
                size='',
                date='',
                type='parent folder',
        )
        for file in files:
            if not file.is_dir():
                name = file.stem
                ext = file.suffix
                ctype = self.guess_type(str(file))
            else:
                name = file.name
                ext = '/'
                ctype = 'folder'

            link = urllib.parse.quote(name + ext, errors='surrogatepass')
            size_str = self.format_size(self.get_path_size(file))
            last_modified = file.lstat().st_mtime
            year, month, day, hh, mm, ss, x, y, z = time.gmtime(last_modified)
            date_str = "{} {:.3} {} {:02}:{:02}:{:02}".format(
                day, self.monthname[month], year, hh, mm, ss)
            if file.is_symlink():
                ext += '@'

            r.add_line(
                link=link,
                name=html.escape(name),
                ext=html.escape(ext),
                size=html.escape(size_str),
                date=html.escape(date_str),
                type=html.escape(ctype)
            )
        encoded = r.get_text().encode('utf-8', 'surrogateescape')
        f = io.BytesIO()
        f.write(encoded)
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        return f

    def get_path_size(self, path):
        """Calculate the total size of a file or a folder."""
        if path.is_dir():
            return sum(map(self.get_path_size, path.iterdir()))
        else:
            return path.stat().st_size

    def format_size(self, size, suffix='B'):
        """Format file size in a human-readable form."""
        size = float(size)
        k = 1024.0
        if size < k and int(size) == size:
            return '{} {}'.format(int(size), suffix)
        for unit in ['','K','M','G','T','P','E','Z']:
            if abs(size) < k:
                return "{:.2f} {}{}".format(size, unit, suffix)
            size /= k
        return "{:.2f} Y{}".format(size, suffix)

    def log_request(self, code='-', size='-'):
        """Log request to stdout and to event listeners."""
        super().log_request(code, size)
        self.request_id = self.server.request_cnt
        self.server.request_cnt += 1
        self.bytes_send = 0
        self.server.fire_event('request', dict(
            id=self.request_id,
            requestline=self.requestline,
            path=urllib.parse.unquote(self.path),
            response=dict(
                code=code,
                short=self.responses[code][0],
                long=self.responses[code][1]
                ),
            headers=dict(self.headers.items()),
            time=self.log_date_time_string(),
            address=self.address_string(),
            bytes_send=self.bytes_send, # = 0
            status="No Data"
        ))

    def copyfile(self, src, dst):
        """Copy data from src to dst, continuously providing status updates."""
        length = 16*1024
        self.server.fire_event('update', dict(
            id=self.request_id,
            status="In Progress"
        ))
        while True:
            buf = src.read(length)
            if not buf:
                break
            try:
                dst.write(buf)
            except ConnectionResetError:
                # The connection was just reset. We're going to log it
                # and leave it for LeekServer.handle_error() to handle
                self.server.fire_event('update', dict(
                    id=self.request_id,
                    status="Reset"
                ))
                raise
            self.bytes_send += len(buf)
            self.server.fire_event('update', dict(
                id=self.request_id,
                bytes_send=self.bytes_send
            ))
        self.server.fire_event('update', dict(
            id=self.request_id,
            status="Finished"
        ))

    def parse_time(self, s):
        """Parse time encoded using the format described in RFC 2616.

        Return timestamp or -1 in case of formatting error.

        """
        if s.endswith('GMT'):
            s = s[:-len('GMT')]
        s = s.replace(',', ' ').replace('-', ' ').split()
        for item in s:
            if ':' in item:
                tm = item
                continue
            for i, m in enumerate(self.monthname):
                if m:
                    if item.startswith(m):
                        month = i
                        break
            else:
                if len(item) == 2:
                    try:
                        day = int(item)
                    except:
                        pass
                elif len(item) == 4:
                    try:
                        year = int(item)
                    except:
                        pass
        s = '{:04} {:02} {:02} {}'.format(year, month, day, tm)
        try:
            tm = time.strptime(s, "%Y %m %d %X")
        except ValueError:
            return -1
        else:
            return calendar.timegm(tm)


    SimpleHTTPRequestHandler.extensions_map.update(
        {
            '.mkv': 'video/x-matroska'
        }
    )


class LeekLogServer(LeekServer):
    def __init__(self, *args, target, **kwargs):
        super().__init__(*args, **kwargs)
        self.target = target

class LeekLogRequestHandler(BaseHTTPRequestHandler):

    server_version = "LeekLogProvider/0.3"

    template = None # To be loaded

    def send_bytes(self, bytes, type):
        self.send_response(200)
        self.send_header("Content-Type", type)
        self.send_header("Content-Length", str(len(bytes)))
        self.end_headers()
        self.wfile.write(bytes)

    def do_GET(self):
        if self.path == '/updates':
            e = self.server.target.events_feed
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            while True:
                if e[0].wait(15):
                    event_type, data, e = e[1:]
                    r = 'event: {}\ndata: {}\n\n'.format(
                        event_type, json.dumps(data))
                    r = r.encode('utf-8', 'surrogateescape')
                    self.wfile.write(r)
                    self.wfile.flush()
                else:
                    self.wfile.write(b': X\n\n')
                    self.wfile.flush()
            return
        if self.headers.get('Referer', '').endswith('/log'):
            if self.path == '/log.js':
                r = self.template['log.js']
                self.send_bytes(r, "application/javascript")
                return
            if self.path == '/styles.css':
                r = self.template['styles.css']
                self.send_bytes(r, "text/css")
                return
        if self.path == '/log':
            r = self.template['log.html']
            self.send_bytes(r, "text/html")
            return
        if self.path == '/root':
            root_url = 'http://{}:{}'
            base_address = self.headers.get('Host', 'localhost')
            if ':' in base_address:
                try:
                    ipaddress.ip_address(base_address)
                except ValueError:
                    last_colon = base_address.rfind(':')
                    base_address = base_address[:last_colon]
            port = self.server.target.socket.getsockname()[1]
            r = root_url.format(base_address, port).encode('utf-8')
            self.send_bytes(r, "text/plain")
            return
        self.send_response(301)
        self.send_header("Location", '/log')
        self.send_header("Cache-Control", 'no-cache')
        self.end_headers()

    def log_request(self, code='-', size='-'):
        pass


def read_templates(path):
    template = dict()
    with (path/'listdir/main.html').open() as f:
        template['main'] = f.read()
    with (path/'listdir/item.html').open() as f:
        template['item'] = f.read()
    with (path/'listdir/style.css').open() as f:
        template['css'] = f.read()

    ListDirFormatter.template = template

    template = dict()
    with (path/'log/log.html').open('rb') as f:
        template['log.html'] = f.read()
    with (path/'log/styles.css').open('rb') as f:
        template['styles.css'] = f.read()
    with (path/'log/log.js').open('rb') as f:
        template['log.js'] = f.read()

    LeekLogRequestHandler.template = template




def run(server_class, handler_class, port,
        log_server_class, log_request_class, log_port):
    print("Starting...")

    server = server_class(('', port), handler_class)
    log_server = log_server_class(('', log_port), log_request_class,
                                  target=server)

    print("Serving HTTP {} on port {}...".format(*server.socket.getsockname()))

    try:
        threading.Thread(target=log_server.serve_forever).start()
        log_url = "http://localhost:{}".format(log_port)
        try:
            webbrowser.open(log_url)
        except Exception:
            pass
        finally:
            print("Web log available at", log_url)
    except Exception:
        print("Failed to strat the logging server")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
        log_server.server_close()
        print("Finished")


leek_path = pathlib.Path(__file__).resolve().parent
read_templates(leek_path)

if __name__ == '__main__':
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8000

    if sys.argv[2:]:
        os.chdir(sys.argv[2])

    run(LeekServer, LeekRequestHandler, port,
        LeekLogServer, LeekLogRequestHandler, port+1)
