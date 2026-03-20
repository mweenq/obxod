import asyncio
import socket
import struct
import os
import ssl
import base64
import sys
import logging
import argparse

# =====================================================
#  DEFAULTS
# =====================================================

DEFAULT_PORT = 1080
DEFAULT_HOST = "127.0.0.1"
DEFAULT_MODE = "auto"

DEFAULT_DC_LIST = [
    "1:149.154.175.50",
    "2:149.154.167.220",
    "3:149.154.175.100",
    "4:149.154.167.220",
    "5:91.108.56.100",
]

FALLBACK_IP = "149.154.167.220"
FALLBACK_DC = 2

CONNECT_TIMEOUT = 10
READ_TIMEOUT = 300
WS_HANDSHAKE_TIMEOUT = 15
UDP_TIMEOUT = 120
UDP_BUFFER_SIZE = 65535

# =====================================================
#  GLOBAL STATE (заполняется в main)
# =====================================================

TG_MODE = DEFAULT_MODE
BIND_HOST = DEFAULT_HOST
BIND_PORT = DEFAULT_PORT
VERBOSE = False

log = logging.getLogger("obxod")

# =====================================================
#  TELEGRAM SUBNETS & DC MAPPING
# =====================================================

TG_SUBNETS = [
    "149.154.160.0/20",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.36.0/23",
    "91.108.38.0/23",
    "91.108.56.0/22",
    "185.76.151.0/24",
]

TG_SUBNETS_V6 = [
    "2001:b28:f23d::",
    "2001:b28:f23f::",
    "2001:67c:4e8::",
]

TG_DC_MAP_EXACT = {
    "149.154.175.50": 1, "149.154.175.51": 1, "149.154.175.52": 1,
    "149.154.175.53": 1, "149.154.175.54": 1, "149.154.175.55": 1,
    "149.154.167.40": 2, "149.154.167.41": 2, "149.154.167.51": 2,
    "149.154.167.220": 2, "149.154.167.221": 2, "149.154.167.222": 2,
    "149.154.175.100": 3, "149.154.175.117": 3, "149.154.175.118": 3,
    "149.154.175.119": 3, "149.154.175.120": 3,
    "149.154.167.91": 4, "149.154.167.92": 4,
    "149.154.167.93": 4, "149.154.167.94": 4,
    "91.108.56.100": 5, "91.108.56.101": 5, "91.108.56.130": 5,
    "91.108.56.131": 5, "91.108.56.160": 5, "91.108.56.161": 5,
    "91.108.56.190": 5, "91.108.56.191": 5,
    "91.108.4.1": 1, "91.108.4.2": 1, "91.108.5.1": 1, "91.108.5.2": 1,
    "91.108.8.1": 2, "91.108.8.2": 2, "91.108.9.1": 2, "91.108.9.2": 2,
    "91.108.12.1": 3, "91.108.12.2": 3, "91.108.13.1": 3, "91.108.13.2": 3,
    "91.108.16.1": 4, "91.108.16.2": 4, "91.108.17.1": 4, "91.108.17.2": 4,
    "91.108.20.1": 5, "91.108.20.2": 5, "91.108.21.1": 5, "91.108.21.2": 5,
}


# =====================================================
#  HELPERS
# =====================================================

def is_frozen() -> bool:
    """Проверяет, запущен ли как скомпилированный EXE (PyInstaller)."""
    return getattr(sys, 'frozen', False)


def pause_on_exit():
    """Пауза перед выходом если EXE запущен без батника."""
    if is_frozen() and sys.stdin and sys.stdin.isatty():
        print()
        input("Нажмите Enter для выхода...")


def parse_dc_ip_list(dc_list: list) -> dict:
    result = {}
    for entry in dc_list:
        entry = entry.strip()
        if not entry:
            continue
        if ":" not in entry:
            raise ValueError(f"Неверный формат: '{entry}', ожидается 'DC:IP'")
        parts = entry.split(":", 1)
        try:
            dc = int(parts[0])
        except ValueError:
            raise ValueError(f"DC должен быть числом: '{parts[0]}'")
        ip = parts[1].strip()
        if not ip:
            raise ValueError(f"Пустой IP для DC {dc}")
        result[dc] = ip
    return result


def _ip_to_int(ip: str) -> int:
    parts = ip.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def _parse_cidr(cidr: str):
    net, bits = cidr.split("/")
    bits = int(bits)
    net_int = _ip_to_int(net)
    mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
    return net_int & mask, mask


_tg_nets = [_parse_cidr(s) for s in TG_SUBNETS]


def is_telegram_ip(ip: str) -> bool:
    if ":" in ip:
        for prefix in TG_SUBNETS_V6:
            if ip.lower().startswith(prefix.rstrip(":")):
                return True
        return False
    try:
        ip_int = _ip_to_int(ip)
    except (ValueError, IndexError):
        return False
    for net, mask in _tg_nets:
        if (ip_int & mask) == net:
            return True
    return False


def get_dc_from_ip(ip: str) -> int:
    if ":" in ip:
        ip_lower = ip.lower()
        for dc in range(1, 6):
            if f":f00{dc}" in ip_lower or f":f{dc}::" in ip_lower:
                return dc
        return FALLBACK_DC

    if ip in TG_DC_MAP_EXACT:
        return TG_DC_MAP_EXACT[ip]

    try:
        octets = ip.split(".")
        o1, o2, o3, o4 = int(octets[0]), int(octets[1]), int(octets[2]), int(octets[3])
    except (ValueError, IndexError):
        return FALLBACK_DC

    if o1 == 149 and o2 == 154 and o3 == 175:
        if o4 == 100 or 110 <= o4 <= 120:
            return 3
        if o4 >= 200:
            return FALLBACK_DC
        return 1

    if o1 == 149 and o2 == 154 and o3 == 167:
        if o4 >= 90:
            return 4
        return 2

    if o1 == 149 and o2 == 154 and 160 <= o3 <= 175:
        if o3 <= 163:
            return 1
        if o3 <= 167:
            return 2
        if o3 <= 171:
            return 3
        return 4

    if o1 == 91 and o2 == 108:
        if o3 in (4, 5):
            return 1
        if o3 in (8, 9):
            return 2
        if o3 in (12, 13):
            return 3
        if o3 in (16, 17):
            return 4
        if o3 in (20, 21, 56, 57, 58, 59):
            return 5
        if o3 in (36, 37, 38, 39):
            return 2

    if o1 == 185 and o2 == 76 and o3 == 151:
        return 2

    return FALLBACK_DC


def get_ws_host(dc_id: int) -> str:
    return f"kws{dc_id}.web.telegram.org"


# =====================================================
#  WEBSOCKET
# =====================================================

def xor_bytes(data: bytes, mask: bytes) -> bytes:
    if not data:
        return b""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ mask[i & 3]
    return bytes(result)


def build_ws_frame(payload: bytes, opcode: int = 0x02, masked: bool = True) -> bytes:
    length = len(payload)
    frame = bytearray([0x80 | opcode])
    mask_bit = 0x80 if masked else 0x00
    if length < 126:
        frame.append(length | mask_bit)
    elif length < 65536:
        frame.append(126 | mask_bit)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(127 | mask_bit)
        frame.extend(struct.pack(">Q", length))
    if masked:
        m = os.urandom(4)
        frame.extend(m)
        frame.extend(xor_bytes(payload, m))
    else:
        frame.extend(payload)
    return bytes(frame)


async def read_ws_frame(reader, timeout=READ_TIMEOUT):
    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        return None
    opcode = header[0] & 0x0F
    is_masked = bool(header[1] & 0x80)
    payload_len = header[1] & 0x7F
    try:
        if payload_len == 126:
            ext = await asyncio.wait_for(reader.readexactly(2), timeout=10)
            payload_len = struct.unpack(">H", ext)[0]
        elif payload_len == 127:
            ext = await asyncio.wait_for(reader.readexactly(8), timeout=10)
            payload_len = struct.unpack(">Q", ext)[0]
        if payload_len > 16 * 1024 * 1024:
            return None
        mask_key = None
        if is_masked:
            mask_key = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        payload = b""
        if payload_len > 0:
            payload = await asyncio.wait_for(reader.readexactly(payload_len), timeout=60)
            if is_masked and mask_key:
                payload = xor_bytes(payload, mask_key)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
        return None
    return (opcode, payload)


# =====================================================
#  RELAY
# =====================================================

async def ws_relay_to_client(ws_reader, ws_writer, client_writer):
    try:
        while True:
            frame = await read_ws_frame(ws_reader)
            if frame is None:
                break
            opcode, payload = frame
            if opcode == 8:
                break
            elif opcode == 9:
                try:
                    pong = build_ws_frame(payload, opcode=0x0A, masked=True)
                    ws_writer.write(pong)
                    await asyncio.wait_for(ws_writer.drain(), timeout=5)
                except Exception:
                    break
            elif opcode == 0x0A:
                continue
            elif opcode in (0, 1, 2):
                if payload:
                    try:
                        client_writer.write(payload)
                        await asyncio.wait_for(client_writer.drain(), timeout=10)
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        break
    except Exception as e:
        log.debug("[WS→Client] %s", e)
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except Exception:
            pass


async def ws_relay_from_client(client_reader, ws_writer):
    try:
        while True:
            try:
                data = await asyncio.wait_for(client_reader.read(65536), timeout=READ_TIMEOUT)
            except asyncio.TimeoutError:
                break
            if not data:
                try:
                    ws_writer.write(build_ws_frame(b"", opcode=0x08, masked=True))
                    await asyncio.wait_for(ws_writer.drain(), timeout=5)
                except Exception:
                    pass
                break
            frame = build_ws_frame(data, opcode=0x02, masked=True)
            try:
                ws_writer.write(frame)
                await asyncio.wait_for(ws_writer.drain(), timeout=10)
            except (ConnectionResetError, BrokenPipeError, OSError, asyncio.TimeoutError):
                break
    except Exception as e:
        log.debug("[Client→WS] %s", e)
    finally:
        try:
            ws_writer.close()
            await ws_writer.wait_closed()
        except Exception:
            pass


async def tcp_relay(reader, writer):
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout=READ_TIMEOUT)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# =====================================================
#  TELEGRAM CONNECT
# =====================================================

async def connect_ws_telegram(dst_ip: str, dst_port: int, dc_id: int, dc_map: dict):
    host_ws = get_ws_host(dc_id)
    ssl_context = ssl.create_default_context()

    targets = []
    mapped_ip = dc_map.get(dc_id)
    if mapped_ip:
        targets.append(mapped_ip)

    if ":" not in dst_ip and dst_ip not in targets:
        resolved_dc = get_dc_from_ip(dst_ip)
        if resolved_dc == dc_id:
            targets.append(dst_ip)
        else:
            log.debug("[WS] IP %s = DC%d, не DC%d — пропуск", dst_ip, resolved_dc, dc_id)

    if FALLBACK_IP not in targets:
        targets.append(FALLBACK_IP)

    r_reader = r_writer = None
    last_error = None

    for ip in targets:
        try:
            log.debug("[WS] Попытка %s:443 (DC%d, SNI=%s)", ip, dc_id, host_ws)
            conn = asyncio.open_connection(ip, 443, ssl=ssl_context, server_hostname=host_ws)
            r_reader, r_writer = await asyncio.wait_for(conn, timeout=CONNECT_TIMEOUT)
            log.debug("[WS] TLS OK → %s:443 (DC%d)", ip, dc_id)
            break
        except ssl.SSLCertVerificationError as e:
            last_error = e
            log.warning("[WS] SSL ошибка %s:443 DC%d: %s", ip, dc_id, e)
            r_reader = r_writer = None
        except Exception as e:
            last_error = e
            log.debug("[WS] %s:443 неудача: %s", ip, e)
            r_reader = r_writer = None

    if r_reader is None:
        raise ConnectionError(f"DC{dc_id}: все попытки провалились — {last_error}")

    key = base64.b64encode(os.urandom(16)).decode("utf-8")
    ws_req = (
        f"GET /apiws HTTP/1.1\r\n"
        f"Host: {host_ws}\r\n"
        f"Origin: https://web.telegram.org\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Protocol: binary\r\n"
        f"\r\n"
    )
    r_writer.write(ws_req.encode("utf-8"))
    await r_writer.drain()

    try:
        resp = await asyncio.wait_for(r_reader.readuntil(b"\r\n\r\n"), timeout=WS_HANDSHAKE_TIMEOUT)
    except asyncio.IncompleteReadError as e:
        resp = e.partial
    except asyncio.TimeoutError:
        r_writer.close()
        raise ConnectionError("WS handshake timeout")

    if b"101" not in resp:
        r_writer.close()
        raise ConnectionError(f"WS handshake failed: {resp[:200]}")

    log.debug("[WS] Handshake OK DC%d (%s)", dc_id, host_ws)
    return r_reader, r_writer


async def connect_direct_tcp(dst_ip: str, dst_port: int):
    r_reader, r_writer = await asyncio.wait_for(
        asyncio.open_connection(dst_ip, dst_port), timeout=CONNECT_TIMEOUT)
    return r_reader, r_writer


async def connect_telegram(dst_ip, dst_port, dc_id, dc_map, client_addr):
    global TG_MODE

    if TG_MODE == "direct":
        r_reader, r_writer = await connect_direct_tcp(dst_ip, dst_port)
        log.info("[Direct] %s → %s:%d DC%d", client_addr, dst_ip, dst_port, dc_id)
        return r_reader, r_writer, False

    if TG_MODE == "ws":
        r_reader, r_writer = await connect_ws_telegram(dst_ip, dst_port, dc_id, dc_map)
        log.info("[WS] %s → %s:%d DC%d", client_addr, dst_ip, dst_port, dc_id)
        return r_reader, r_writer, True

    # auto
    if dst_port == 443:
        r_reader, r_writer = await connect_ws_telegram(dst_ip, dst_port, dc_id, dc_map)
        log.info("[WS] %s → %s:%d DC%d", client_addr, dst_ip, dst_port, dc_id)
        return r_reader, r_writer, True

    try:
        r_reader, r_writer = await connect_direct_tcp(dst_ip, dst_port)
        log.info("[Direct] %s → %s:%d DC%d", client_addr, dst_ip, dst_port, dc_id)
        return r_reader, r_writer, False
    except Exception as e:
        log.debug("[Direct] %s:%d fail: %s → fallback WS", dst_ip, dst_port, e)

    r_reader, r_writer = await connect_ws_telegram(dst_ip, 443, dc_id, dc_map)
    log.info("[WS-FB] %s → %s:%d→443 DC%d", client_addr, dst_ip, dst_port, dc_id)
    return r_reader, r_writer, True


# =====================================================
#  UDP ASSOCIATE
# =====================================================

class UdpRelayProtocol(asyncio.DatagramProtocol):
    def __init__(self, client_addr, loop, timeout=UDP_TIMEOUT):
        self.client_addr = client_addr
        self.loop = loop
        self.transport = None
        self.remote_transports = {}
        self.remote_protocols = {}
        self.timeout = timeout
        self._timeout_handle = None
        self._closed = False

    def connection_made(self, transport):
        self.transport = transport
        self._reset_timeout()

    def _reset_timeout(self):
        if self._timeout_handle:
            self._timeout_handle.cancel()
        self._timeout_handle = self.loop.call_later(self.timeout, self._on_timeout)

    def _on_timeout(self):
        log.info("[UDP] Таймаут %s", self.client_addr)
        self.close()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._timeout_handle:
            self._timeout_handle.cancel()
        if self.transport:
            self.transport.close()
        for t in self.remote_transports.values():
            try:
                t.close()
            except Exception:
                pass
        self.remote_transports.clear()

    def datagram_received(self, data: bytes, addr):
        if self._closed:
            return
        self._reset_timeout()
        self.client_addr = addr

        if len(data) < 4:
            return
        frag = data[2]
        if frag != 0:
            return

        atyp = data[3]
        offset = 4

        try:
            if atyp == 0x01:
                if len(data) < offset + 6:
                    return
                dst_ip = socket.inet_ntoa(data[offset:offset + 4])
                offset += 4
            elif atyp == 0x03:
                domain_len = data[offset]
                offset += 1
                if len(data) < offset + domain_len + 2:
                    return
                dst_ip = data[offset:offset + domain_len].decode("utf-8")
                offset += domain_len
            elif atyp == 0x04:
                if len(data) < offset + 18:
                    return
                dst_ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
                offset += 16
            else:
                return

            dst_port = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
            payload = data[offset:]
        except Exception:
            return

        log.debug("[UDP] %s → %s:%d (%d B)", addr, dst_ip, dst_port, len(payload))

        key = (dst_ip, dst_port)
        if key in self.remote_transports:
            try:
                self.remote_transports[key].sendto(payload, (dst_ip, dst_port))
            except Exception:
                pass
        else:
            asyncio.ensure_future(
                self._create_remote(key, dst_ip, dst_port, payload, atyp),
                loop=self.loop)

    async def _create_remote(self, key, dst_ip, dst_port, payload, atyp):
        try:
            if atyp == 0x03:
                infos = await self.loop.getaddrinfo(dst_ip, dst_port, type=socket.SOCK_DGRAM)
                if not infos:
                    return
                family = infos[0][0]
                resolved = infos[0][4][:2]
            elif atyp == 0x04:
                family = socket.AF_INET6
                resolved = (dst_ip, dst_port)
            else:
                family = socket.AF_INET
                resolved = (dst_ip, dst_port)

            protocol = UdpRemoteProtocol(self, key, dst_ip, dst_port)
            transport, _ = await self.loop.create_datagram_endpoint(
                lambda: protocol, family=family, remote_addr=resolved)

            self.remote_transports[key] = transport
            self.remote_protocols[key] = protocol
            transport.sendto(payload)
        except Exception as e:
            log.debug("[UDP] remote %s:%d error: %s", dst_ip, dst_port, e)

    def send_to_client(self, data: bytes, remote_ip: str, remote_port: int):
        if self._closed or not self.transport:
            return
        self._reset_timeout()

        header = bytearray(b"\x00\x00\x00")
        try:
            packed = socket.inet_aton(remote_ip)
            header.append(0x01)
            header.extend(packed)
        except OSError:
            try:
                packed = socket.inet_pton(socket.AF_INET6, remote_ip)
                header.append(0x04)
                header.extend(packed)
            except OSError:
                encoded = remote_ip.encode("utf-8")
                header.append(0x03)
                header.append(len(encoded))
                header.extend(encoded)

        header.extend(struct.pack("!H", remote_port))
        header.extend(data)

        try:
            self.transport.sendto(bytes(header), self.client_addr)
        except Exception as e:
            log.debug("[UDP] → client error: %s", e)

    def error_received(self, exc):
        log.debug("[UDP] client socket error: %s", exc)

    def connection_lost(self, exc):
        self.close()


class UdpRemoteProtocol(asyncio.DatagramProtocol):
    def __init__(self, relay, key, remote_ip, remote_port):
        self.relay = relay
        self.key = key
        self.remote_ip = remote_ip
        self.remote_port = remote_port

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        self.relay.send_to_client(data, addr[0], addr[1])

    def error_received(self, exc):
        log.debug("[UDP] remote error %s:%d: %s", self.remote_ip, self.remote_port, exc)

    def connection_lost(self, exc):
        self.relay.remote_transports.pop(self.key, None)
        self.relay.remote_protocols.pop(self.key, None)


async def handle_udp_associate(reader, writer, client_addr, bind_host):
    loop = asyncio.get_event_loop()
    protocol = None

    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: UdpRelayProtocol(client_addr, loop),
            local_addr=(bind_host, 0))

        udp_addr = transport.get_extra_info("sockname")
        udp_port = udp_addr[1]
        log.info("[UDP] Сессия %s → порт %d", client_addr, udp_port)

        reply = bytearray(b"\x05\x00\x00")
        try:
            packed_ip = socket.inet_aton(bind_host)
            reply.append(0x01)
            reply.extend(packed_ip)
        except OSError:
            reply.append(0x01)
            reply.extend(socket.inet_aton("127.0.0.1"))
        reply.extend(struct.pack("!H", udp_port))

        writer.write(bytes(reply))
        await writer.drain()

        try:
            while True:
                data = await asyncio.wait_for(reader.read(1024), timeout=UDP_TIMEOUT)
                if not data:
                    break
        except (asyncio.TimeoutError, ConnectionError):
            pass

    except Exception as e:
        log.error("[UDP] %s: %s", client_addr, e)
        writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
        await writer.drain()
    finally:
        if protocol:
            try:
                protocol.close()
            except Exception:
                pass
        log.info("[UDP] Закрыто %s", client_addr)


# =====================================================
#  SOCKS5 HANDLER
# =====================================================

async def handle_socks5(reader, writer, dc_map: dict, bind_host: str):
    client_addr = writer.get_extra_info("peername")
    r_writer = None

    try:
        header = await asyncio.wait_for(reader.readexactly(2), timeout=10)
        if header[0] != 0x05:
            return

        n_methods = header[1]
        await asyncio.wait_for(reader.readexactly(n_methods), timeout=10)
        writer.write(b"\x05\x00")
        await writer.drain()

        req = await asyncio.wait_for(reader.readexactly(4), timeout=10)
        if req[0] != 0x05:
            return

        cmd = req[1]
        atyp = req[3]

        if atyp == 0x01:
            raw = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            dst_ip = socket.inet_ntoa(raw)
        elif atyp == 0x03:
            dlen = (await asyncio.wait_for(reader.readexactly(1), timeout=10))[0]
            dst_ip = (await asyncio.wait_for(reader.readexactly(dlen), timeout=10)).decode()
        elif atyp == 0x04:
            raw = await asyncio.wait_for(reader.readexactly(16), timeout=10)
            dst_ip = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            writer.write(b"\x05\x08\x00\x01" + b"\x00" * 6)
            await writer.drain()
            return

        dst_port = struct.unpack("!H",
                                 await asyncio.wait_for(reader.readexactly(2), timeout=10))[0]

        # CONNECT
        if cmd == 0x01:
            is_tg = is_telegram_ip(dst_ip)

            if is_tg:
                dc_id = get_dc_from_ip(dst_ip)
                log.debug("[SOCKS5] %s → %s:%d DC%d", client_addr, dst_ip, dst_port, dc_id)

                try:
                    r_reader, r_writer, is_ws = await connect_telegram(
                        dst_ip, dst_port, dc_id, dc_map, client_addr)
                except (ConnectionError, OSError) as e:
                    log.error("[Connect] %s:%d DC%d: %s", dst_ip, dst_port, dc_id, e)
                    writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
                    await writer.drain()
                    return

                writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
                await writer.drain()

                if is_ws:
                    await asyncio.gather(
                        ws_relay_to_client(r_reader, r_writer, writer),
                        ws_relay_from_client(reader, r_writer),
                        return_exceptions=True)
                else:
                    await asyncio.gather(
                        tcp_relay(reader, r_writer),
                        tcp_relay(r_reader, writer),
                        return_exceptions=True)
            else:
                log.info("[TCP] %s → %s:%d", client_addr, dst_ip, dst_port)
                try:
                    r_reader, r_writer = await connect_direct_tcp(dst_ip, dst_port)
                except Exception as e:
                    log.error("[TCP] %s:%d: %s", dst_ip, dst_port, e)
                    writer.write(b"\x05\x05\x00\x01" + b"\x00" * 6)
                    await writer.drain()
                    return

                writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
                await writer.drain()

                await asyncio.gather(
                    tcp_relay(reader, r_writer),
                    tcp_relay(r_reader, writer),
                    return_exceptions=True)

        # UDP ASSOCIATE
        elif cmd == 0x03:
            log.info("[UDP] %s ASSOCIATE %s:%d", client_addr, dst_ip, dst_port)
            await handle_udp_associate(reader, writer, client_addr, bind_host)

        # BIND / другое
        else:
            writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
            await writer.drain()

    except asyncio.TimeoutError:
        log.debug("[SOCKS5] Таймаут %s", client_addr)
    except (ConnectionResetError, BrokenPipeError):
        log.debug("[SOCKS5] Сброс %s", client_addr)
    except Exception as e:
        log.error("[SOCKS5] %s: %s", client_addr, e)
    finally:
        for w in (writer, r_writer):
            if w:
                try:
                    w.close()
                    await w.wait_closed()
                except Exception:
                    pass


# =====================================================
#  SERVER
# =====================================================

VERSION = "0.1b"

BANNER = r"""
		
         dP                               dP 
         88                               88 
.d8888b. 88d888b. dP.  .dP .d8888b. .d888b88 
88'  `88 88'  `88  `8bd8'  88'  `88 88'  `88 
88.  .88 88.  .88  .d88b.  88.  .88 88.  .88 
`88888P' 88Y8888' dP'  `dP `88888P' `88888P8 
        Telegram Bypass,   v.0.1b 
"""


async def run_server(host: str, port: int, dc_map: dict,
                     stop_event: asyncio.Event = None):

    async def handler(reader, writer):
        await handle_socks5(reader, writer, dc_map, host)

    server = await asyncio.start_server(handler, host, port)

    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)

    print(BANNER.format(version=VERSION))
    print(f"  Слушаю:       {addrs}")
    print(f"  Режим:        {TG_MODE}")
    print(f"  Логи:         {'ВКЛЮЧЕНЫ' if LOGS_ENABLED else 'ВЫКЛЮЧЕНЫ'}")  # <--- НОВОЕ
    print(f"  Звонки UDP:   да")
    print(f"  Таймауты:     connect={CONNECT_TIMEOUT}s read={READ_TIMEOUT}s udp={UDP_TIMEOUT}s")
    print(f"  DC маппинги:")
    for dc, ip in sorted(dc_map.items()):
        print(f"    DC{dc} → {ip}")
    print()
    print(f"  Настрой в Telegram:")
    print(f"    Прокси → SOCKS5 → {host}:{port} (скопировать и вставить)")
    print()
    print("=" * 54)
    print()

    if stop_event:
        async with server:
            await stop_event.wait()
            server.close()
            await server.wait_closed()
    else:
        async with server:
            await server.serve_forever()


# =====================================================
#  MAIN + CLI
# =====================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="obxod",
        description="obxod — SOCKS5 прокси для обхода DPI-блокировок Telegram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  obxod                          # запуск с дефолтами (127.0.0.1:1080, auto)
  obxod -p 9050                  # другой порт
  obxod -b 0.0.0.0 -p 1080       # слушать на всех интерфейсах
  obxod -m ws                    # всегда WebSocket (максимальный обход)
  obxod -m direct                # прямое подключение (без обхода)
  obxod --dc 2:1.2.3.4           # кастомный IP для DC2
  obxod --logs True             
  obxod --logs False  (по умолчанию)

Режимы (-m / --mode):
  auto     порт 443 → WebSocket, остальные → TCP (fallback → WS)
  ws       всегда WebSocket через порт 443
  direct   прямой TCP без обхода

Запуск осуществляется через .bat файлы
""")

    parser.add_argument("-p", "--port",
                        type=int, default=DEFAULT_PORT,
                        help=f"порт прокси (по умолчанию: {DEFAULT_PORT})")

    parser.add_argument("-b", "--bind",
                        default=DEFAULT_HOST,
                        help=f"адрес для привязки (по умолчанию: {DEFAULT_HOST})")

    parser.add_argument("-m", "--mode",
                        choices=["auto", "ws", "direct"],
                        default=DEFAULT_MODE,
                        help="режим подключения к Telegram (по умолчанию: auto)")

    parser.add_argument("--dc",
                        action="append", metavar="N:IP",
                        help="задать IP для DC, например: --dc 2:149.154.167.220")

    parser.add_argument("--logs",
                        type=str,
                        choices=["True", "False"],
                        default="False",
                        help="Показывать логи (True/False). По умолчанию: False")

    parser.add_argument("-V", "--version",
                        action="version",
                        version=f"obxod {VERSION}")

    return parser


def main():
    global TG_MODE, BIND_HOST, BIND_PORT, LOGS_ENABLED  # <-- НОВОЕ

    parser = build_parser()
    args = parser.parse_args()

    # --- Применяем аргументы ---
    TG_MODE = args.mode
    BIND_HOST = args.bind
    BIND_PORT = args.port
    LOGS_ENABLED = args.logs == "True"   # <-- НОВОЕ

    # --- Логирование ---
    log_level = logging.DEBUG if LOGS_ENABLED else logging.CRITICAL  # CRITICAL = никаких логов
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # --- DC маппинг ---
    dc_list_raw = args.dc if args.dc else DEFAULT_DC_LIST
    try:
        dc_map = parse_dc_ip_list(dc_list_raw)
    except ValueError as e:
        print(f"[!] Ошибка в --dc: {e}")
        pause_on_exit()
        sys.exit(1)

    # --- Валидация порта ---
    if not (1 <= args.port <= 65535):
        print(f"[!] Порт {args.port} вне диапазона 1-65535")
        pause_on_exit()
        sys.exit(1)

    # --- Запуск ---
    try:
        asyncio.run(run_server(args.bind, args.port, dc_map))
    except KeyboardInterrupt:
        print("\n[*] Остановлено (Ctrl+C)")
    except OSError as e:
        if "address already in use" in str(e).lower() or e.errno == 10048:
            print(f"\n[!] Порт {args.port} уже занят! Выберите другой: obxod -p ПОРТ")
        elif "address not available" in str(e).lower() or e.errno == 10049:
            print(f"\n[!] Адрес {args.bind} недоступен! Проверьте --bind")
        else:
            print(f"\n[!] Ошибка сети: {e}")
        pause_on_exit()
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Критическая ошибка: {e}")
        pause_on_exit()
        sys.exit(1)


if __name__ == "__main__":
    main()