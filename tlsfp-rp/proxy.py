#!/usr/bin/env python
"""
This module is a reverse proxy server.
It resolves HTTPS connections from clients and forwards them to an upstream server via HTTP.
It also handles HTTP connections and redirects them to HTTPS.
If possible, this module conducts TLS fingerprinting via JA3 and JA4, and adds the
fingerprints as HTTP request headers to the client's requests before forwarding them to the
upstream server.
"""

import argparse
import json
import logging
from curio.socket import IPPROTO_TCP, TCP_NODELAY
from curio.network import tcp_server
from curio import run, spawn, socket, ssl
from tlsfp import client_hello_data, make_ja3, make_ja4, parse_tls_record
from http_helpers import parse_request

BLOCK_IP_SUBDOMAIN = False
DEBUG_MODE = True
DOMAIN = "localhost"
UPSTREAM_HOST = "nginx"
UPSTREAM_PORT = 80

logging.basicConfig(
    format='%(asctime)s %(levelname)s - %(message)s',
    level=logging.DEBUG if DEBUG_MODE else logging.INFO
)

INFO = logging.info
DEBUG = logging.debug
WARN = logging.warning
ERROR = logging.error


def parse_args():
    """Parse cli arguments"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", type=str, default="/tmp/server.key")
    parser.add_argument("--cert", type=str, default="/tmp/server.crt")
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--domain", type=str, default="localhost")
    parser.add_argument("--upstream-host", type=str, default="nginx")
    parser.add_argument("--upstream-port", type=int, default=80)
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--https-port", type=int, default=443)
    parser.add_argument("--debug", action="store_true", default=False)
    return parser.parse_args()


async def create_upstream_connection():
    """Create and return a new TCP connection to Nginx."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    await s.connect((UPSTREAM_HOST, UPSTREAM_PORT))
    s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
    return s


async def proxy_request(req_data, addr, conn, ja3=None, ja4=None):
    """Proxy the request to Nginx with JA3 and JA4 headers (if available) and return the response."""
    s = await create_upstream_connection()
    try:
        # Split the request into headers and body
        DEBUG(f"Splitting request into headers and body, {req_data.decode()}")
        headers, body = req_data.split(b'\r\n\r\n', 1) if b'\r\n\r\n' in req_data else (req_data, b'')

        # Decode headers and split into lines
        header_lines = headers.decode().split("\r\n")
        INFO(f"Proxying request from {addr[0]}: {header_lines[0]}")

        # Trivia: if the client sets the X-Real-IP header, we will have two and Python will combine them
        header_lines.append(f"X-REAL-IP: {addr[0]}")
        # Trust this header upstream
        header_lines.append(f"X-REAL-IP-TLSFP: {addr[0]}")

        header_lines.append("X-REAL-PROTO: https")
        if ja3 and ja4:
            header_lines.append(f"JA3: {json.dumps(ja3)}")
            header_lines.append(f"JA4: {json.dumps(ja4)}")
        else:
            header_lines.append("X-TLS-SESSION-REUSE: likely")

        # Reconstruct the request with modified headers and original body
        new_headers = "\r\n".join(header_lines).encode()
        DEBUG(f"Headers: {new_headers}")
        DEBUG(f"Body: {body}")

        new_req_data = new_headers + b'\r\n\r\n' + body

        DEBUG(f"Sending request to upstream, total length: {len(new_req_data)}")
        DEBUG(f"Body length: {len(body)}")

        # Send to backend
        await s.sendall(new_req_data)

        # Receive response
        buffer = bytearray()
        while True:
            part = await s.recv(8192)
            if not part:
                break
            buffer.extend(part)
            DEBUG(f"Received {len(part)} bytes from upstream, total buffer size: {len(buffer)}")

            if b'\r\n\r\n' in buffer:
                headers, body = buffer.split(b'\r\n\r\n', 1)
                content_length = None
                for line in headers.split(b'\r\n'):
                    if line.lower().startswith(b'content-length:'):
                        content_length = int(line.split(b':', 1)[1].strip())
                        DEBUG(f"Found Content-Length: {content_length}")
                        break

                if content_length is not None and len(body) >= content_length:
                    DEBUG(f"Sending complete response, length: {len(buffer)}")
                    await conn.sendall(buffer)
                    buffer.clear()
                    break

        if buffer:
            DEBUG(f"Sending remaining buffer, length: {len(buffer)}")
            # Send to client
            await conn.sendall(buffer)

    except Exception as e:
        ERROR(f"Exception in proxy_request: {type(e).__name__}, {str(e)}")
    finally:
        await s.close()


async def handle_https(conn, addr):
    """Handles each new HTTPS connection"""
    conn.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)

    try:
        peek = await conn.recv(1024, socket.MSG_PEEK)
        conn = await tls.wrap_socket(conn, server_side=True)

        # Read the entire request
        buffer = bytearray()
        while True:
            chunk = await conn.recv(8192)
            if not chunk:
                break
            buffer.extend(chunk)

            # Check if we've received the entire request
            if b'\r\n\r\n' in buffer:
                headers, body = buffer.split(b'\r\n\r\n', 1)
                headers = headers.decode('utf-8', errors='ignore')
                content_length = None
                for line in headers.split('\r\n'):
                    if line.lower().startswith('content-length:'):
                        content_length = int(line.split(':', 1)[1].strip())
                        break

                if content_length is None or len(body) >= content_length:
                    break

        buf = bytes(buffer)
        DEBUG(f"{addr[0]} Received complete request, length: {len(buf)}")

        if BLOCK_IP_SUBDOMAIN:
            # Check if the request is for the "ip" subdomain
            try:
                _req, _path, headers, _body = parse_request(buf)
                host_header = headers.get('Host', '')
                if host_header == f"ip.{DOMAIN}":
                    DEBUG(f"(Blocking request from {addr[0]} for {host_header})")
                    await conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    await conn.close()
                    return
            except Exception as e:
                DEBUG(f"Error parsing request for ip subdomain check: {e}")

        ja3 = None
        ja4 = None

        if peek and peek[:3] == b'\x16\x03\x01':
            DEBUG(f"{addr[0]} Received request w/ TLS Client Hello")

            try:
                tls_record_data = parse_tls_record(peek).data.data

                try:
                    ja3 = make_ja3(client_hello_data(tls_record_data))
                    DEBUG(f"{addr[0]} Successfully created JA3: {ja3['ja3']}")
                except Exception as e:
                    ERROR(f"{addr[0]} TLS JA3 fingerprinting failed {addr[0]}: {type(e).__name__}, {str(e)}")
                    ERROR(e, exc_info=True)

                try:
                    ja4 = make_ja4(client_hello_data(tls_record_data))
                    DEBUG(f"{addr[0]} Successfully created JA4: {ja4['ja4']}")
                except Exception as e:
                    ERROR(f"{addr[0]} TLS JA4 fingerprinting failed {addr[0]}: {type(e).__name__}, {str(e)}")
                    ERROR(e, exc_info=True)
            except Exception as e:
                ERROR(f"{addr[0]} Parsing TLS record failed {addr[0]}: {type(e).__name__}, {str(e)}")
                ERROR(e, exc_info=True)

        else:
            DEBUG(f"{addr[0]} Not a TLS handshake. Proxying without fingerprinting.")

        if buf:
            await proxy_request(buf, addr, conn, ja3, ja4)
        else:
            WARN(f"{addr[0]} Received empty buffer after TLS handshake from {addr[0]}")

    except ssl.SSLError as e:
        WARN(f"{addr[0]} SSL Error in handle_https: {e}")
    except Exception as e:
        ERROR(f"{addr[0]}sException in handle_https: {type(e).__name__}, {str(e)}")
    finally:
        await conn.close()
        DEBUG(f"{addr[0]} Closed connection from {addr}")


async def handle_http(conn, addr):
    """Handles HTTP connections and redirects to HTTPS"""
    DEBUG(f"Handling HTTP connection from {addr}")
    try:
        buf = await conn.recv(4096)

        if buf:
            try:
                # Decode the buffer if it's bytes, otherwise use it as is
                _req, path, headers, _body = parse_request(buf)
                host = headers.get('Host', DOMAIN)

                redirect_url = f"https://{host}{path}"
                response = f"HTTP/1.1 301 Moved Permanently\r\nLocation: {redirect_url}\r\nConnection: close\r\n\r\n"

                DEBUG(f"Redirecting HTTP request to: {redirect_url}")
                await conn.sendall(response.encode())
            except Exception as _e:
                WARN(f"Error parsing HTTP request: {_e} {buf}")
                await conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        else:
            WARN("Received empty buffer on HTTP connection")
    except Exception as __e:
        ERROR(f"Exception in handle_http: {__e}")
    finally:
        await conn.close()
        INFO(f"Closed HTTP connection from {addr}")


async def main(_args):
    """
    Main function that starts the HTTPS and HTTP servers concurrently.
    """
    INFO(f"Servers starting HTTP on port {_args.http_port}, HTTPS on port {_args.https_port}")

    async def run_https_server():
        await tcp_server(_args.host, _args.https_port, handle_https)

    async def run_http_server():
        await tcp_server(_args.host, _args.http_port, handle_http)

    # Start both servers concurrently
    https_task = await spawn(run_https_server)
    http_task = await spawn(run_http_server)

    # Wait for both tasks to complete (which they shouldn't)
    await https_task.join()
    await http_task.join()


if __name__ == "__main__":
    try:
        args = parse_args()
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(args.cert, args.key)
        tls.sess_cache_size = 128
        tls.sess_cache_timeout = 300

        UPSTREAM_HOST = args.upstream_host
        UPSTREAM_PORT = args.upstream_port
        DOMAIN = args.domain
        DEBUG_MODE = args.debug

        if DEBUG_MODE:
            INFO("ATTENTION. Running in debug mode. This is not recommended for production.")

        run(main(args))
    except KeyboardInterrupt as e:
        logging.error('Keyboard interrupt. Exiting.')
        raise SystemExit(1) from e
