from datetime import datetime, timezone

SERVER_VERSION = 'testing/1.2.3'

METHODS = ('GET', 'HEAD', 'POST', 'PUT', 'DELETE',
           'CONNECT', 'OPTIONS', 'TRACE', 'PATCH')

STATUS_CODE_MSG = {
    200: 'OK',
    404: 'Not Found',
    405: 'Method Not Allowed',
    500: 'Internal Server Error'
}

RESP_TEMPLATE = '''\
HTTP/1.1 {} {}
Date: {}
Server: {}
Content-Length: {}
Content-Type: {}
Connection: close

'''


def is_http_request(buf: bytes):
    req = buf[:8].decode('ascii', errors='ignore')
    return any(m in req for m in METHODS)


def parse_request(buf: bytes):
    request = buf.split(b'\r\n\r\n', 1)
    headers_raw = request[0].decode('utf-8', errors='ignore')
    body = request[1] if len(request) > 1 else b''

    lines = headers_raw.split('\r\n')
    req, path, _ = lines[0].split(' ')
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    return req, path, headers, body


def http_resp(body='', ctype='text/html; charset=utf-8', status_code=200):
    resp = RESP_TEMPLATE.format(
        str(status_code),
        STATUS_CODE_MSG[status_code],
        datetime.now(timezone.utc),
        SERVER_VERSION,
        str(len(body.encode())),
        ctype
    )
    if body:
        resp += body
    return resp
