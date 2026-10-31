"""Ephemeral CI proxy: TLS to exact public project CDN read-only paths only."""
import http.client
import ipaddress
import os
import socket
import socketserver
import ssl
import sys
import urllib.parse

ALLOW = {"jscdn.tscircuit.com", "modelcdn.tscircuit.com"}
EXACT = {
  "/jscad_models/nema17_backfaceholes.glb": "",
  "/jscad_models/nema17_backfaceholes_jstph6.glb": "",
  "/jscad_models/flexscreen_w26.7mm_h19.26mm_sitsflat.glb": "",
}
ASSETS = {
  "C165948": "617b05f9bba7410b96c001093d8189e4",
  "C2829401": "cefd4596db214da394d9632b2b88f8f2",
  "C283259": "84cf6c2b182949329e473e9158b1fb00",
  "C7502694": "ca55f7f4aa2143938eb241550bbe4129",
  "C93965": "2d0fd2703afb4f81a9dfc54e2181a624",
}
DOWNLOADS = {"4e90b6d8552a4e058d9ebe9d82e11f3a": "C9900017879", "76b360a9d4c54384a4e47d7e5af156df": "C2040"}

def allowed_get(host, path):
    p = urllib.parse.urlsplit(path)
    if p.scheme or p.netloc or ".." in urllib.parse.unquote(p.path) or "\\" in p.path:
        return False
    if host == "jscdn.tscircuit.com":
        return p.path == "/@tscircuit/eecircuit-engine/1.7.6/+esm" and not p.query
    if host != "modelcdn.tscircuit.com":
        return False
    if p.path in EXACT:
        return not p.query
    pairs = urllib.parse.parse_qsl(p.query, keep_blank_values=True, strict_parsing=True)
    if len(pairs) != len(dict(pairs)):
        return False
    query = dict(pairs)
    if query.get("cachebust_origin", "") != "":
        return False
    query.pop("cachebust_origin", None)
    if p.path == "/easyeda_models/download":
        return len(query) == 2 and DOWNLOADS.get(query.get("uuid")) == query.get("pn")
    import re
    match = re.fullmatch(r"/easyeda_models/assets/(C[0-9]+)\.(obj|step)", p.path)
    return bool(match and len(query) == 1 and ASSETS.get(match.group(1)) == query.get("uuid"))

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.environ['R119_CERT'], os.environ['R119_KEY'])
ctx.set_alpn_protocols(['http/1.1'])

class SafeHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        # Resolve once, reject all non-public addresses, dial the verified IP,
        # and still validate the certificate against the allowed hostname.
        infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
        if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise RuntimeError("CDN DNS resolved non-public address")
        error = None
        for address in sorted(addresses, key=lambda a: ':' in a):
            try:
                raw = socket.create_connection((address, self.port), timeout=self.timeout)
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except OSError as exc:
                error = exc
        raise RuntimeError("no public CDN address reachable") from error

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(130)
        try:
            initial = sock.makefile('rb', buffering=0)
            line = initial.readline(8192).decode('ascii').strip()
            method, target, _ = line.split(' ', 2)
            connect_headers = set()
            while True:
                header = initial.readline(8192)
                if header in (b'\r\n', b'\n', b''):
                    break
                connect_headers.add(header.split(b':', 1)[0].strip().lower())
            if method != 'CONNECT' or connect_headers.intersection({b'authorization', b'cookie', b'proxy-authorization'}) or target not in {host + ':443' for host in ALLOW}:
                sock.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
                print('DENY_CONNECT', flush=True)
                return
            host = target[:-4]
            sock.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            tls = ctx.wrap_socket(sock, server_side=True)
            reader = tls.makefile('rb', buffering=0)
            request_line = reader.readline(8192).decode('ascii').strip()
            verb, path, _ = request_line.split(' ', 2)
            header_names = set()
            while True:
                header = reader.readline(8192)
                if header in (b'\r\n', b'\n', b''):
                    break
                header_names.add(header.split(b':', 1)[0].strip().lower())
            parsed = urllib.parse.urlsplit(path)
            clean = parsed.path
            if verb != 'GET' or header_names.intersection({b'authorization', b'cookie', b'proxy-authorization'}) or not allowed_get(host, path):
                tls.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                print('DENY_REQUEST', flush=True)
                return
            conn = SafeHTTPSConnection(host, 443, timeout=120, context=ssl.create_default_context())
            conn.request('GET', path, headers={'User-Agent': 'r119-isolated-public-dependency-validation', 'Accept': '*/*', 'Accept-Encoding': 'identity', 'Connection': 'close'})
            response = conn.getresponse()
            # Never follow redirects or forward authentication, cookies, or request headers.
            if 300 <= response.status < 400:
                tls.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                print('DENY_REDIRECT', host, clean, response.status, flush=True)
                return
            headers = [f'HTTP/1.1 {response.status} {response.reason}', 'Connection: close']
            for name in ('Content-Type', 'Content-Length', 'Content-Encoding'):
                value = response.getheader(name)
                if value:
                    headers.append(f'{name}: {value}')
            tls.sendall(('\r\n'.join(headers) + '\r\n\r\n').encode('latin1'))
            size = 0
            while True:
                chunk = response.read(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > 100_000_000:
                    raise RuntimeError('response exceeds 100 MB cap')
                tls.sendall(chunk)
            print('GET', host, clean, response.status, size, flush=True)
            conn.close()
        except Exception as exc:
            print('PROXY_ERROR', type(exc).__name__, flush=True)
        finally:
            try:
                sock.close()
            except OSError:
                pass

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(('172.29.119.1', 18888), Handler) as server:
    print('READY GET-only project CDN proxy', flush=True)
    server.serve_forever()
