#!/usr/bin/env python3
import argparse
import ipaddress
import random
import socket
import struct
import time

ETHERTYPE_IPV4 = 0x0800
ETHERNET_HARDWARE_TYPE = 1
BROADCAST_ADDRESS = b"\xff" * 6
IPV4_HEADER_LENGTH = 20
IPV4_VERSION_AND_HEADER_LENGTH = 0x45
IPV4_IDENTIFIER = 1
IPV4_TTL = 64
TCP_HEADER_LENGTH = 20
TCP_WINDOW = 64240
TCP_SYN = 0x02
TCP_FIN = 0x01
TCP_ACK = 0x10
TCP_PUSH = 0x08
CLIENT_SEQUENCE = 1000
SERVER_SEQUENCE = 5000
FTP_PORT = 21
HTTP_PORT = 80
CAPTURE_SOURCE_PORT = 60455
SOURCE_PORT_RANGE = (40000, 64000)
PACKET_INTERVAL_SECONDS = 0.02
FTP_COMMAND = b"CWD " + b"x" * 1200 + b"\r\n"
FTP_EXCHANGES = (
    (False, b"220 FTP ready\r\n"),
    (True, b"USER anonymous\r\n"),
    (False, b"331 Password required\r\n"),
    (True, b"PASS guest@example.invalid\r\n"),
    (False, b"230 Login successful\r\n"),
    (True, FTP_COMMAND),
    (False, b"550 Directory unavailable\r\n"),
)
HTTP_PROBES = (
    ("apache-path", "GET", "/icons/.%2e/%2e%2e/.%2e/probe-example.txt", (), b"", b""),
    ("apache-path-double", "GET", "/icons/.%%32%65/.%%32%65/probe-example.txt", (), b"", b""),
    ("citrix-path", "GET", "/vpn/../vpns/probe-example.txt", (), b"", b""),
    ("http-ldap", "GET", "/", (("User-Agent", "${jndi:ldap://"),), b"", b""),
    ("http-rmi", "GET", "/", (("User-Agent", "${jndi:rmi://"),), b"", b""),
    ("http-cookie", "GET", "/", (("Cookie", "probe=() {"),), b"", b""),
    (
        "http-form", "POST", "/probe-example.php",
        (("Content-Type", "application/x-www-form-urlencoded"),),
        b"_method=__construct&filter[]=assert&method=get&server[REQUEST_METHOD]=", b"",
    ),
    (
        "http-agent-nmap", "GET", "/",
        (("User-Agent", "Mozilla/5.0 (compatible; Nmap Scripting Engine)"),), b"", b"",
    ),
    ("http-agent-nse", "GET", "/", (("User-Agent", "Nmap NSE"),), b"", b""),
    ("http-response-uid", "GET", "/", (), b"", b"uid=0(root) gid=0(root) groups=0(root)\n"),
)
PROBE_NAMES = ("ftp-cwd",) + tuple(probe[0] for probe in HTTP_PROBES)

def calculateChecksum(data):
    padded_data = data + b"\x00" * (len(data) % 2)
    words = struct.unpack("!" + "H" * (len(padded_data) // 2), padded_data)
    checksum_total = sum(words)
    while checksum_total >> 16:
        checksum_total = (checksum_total & 0xFFFF) + (checksum_total >> 16)

    return (~checksum_total) & 0xFFFF

def buildTcpSegment(source_address, target_address, source_port, target_port, sequence, acknowledgment, flags, payload):
    tcp_header = struct.pack(
        "!HHIIBBHHH", source_port, target_port, sequence, acknowledgment,
        (TCP_HEADER_LENGTH // 4) << 4, flags, TCP_WINDOW, 0, 0,
    )
    segment_length = len(tcp_header) + len(payload)
    pseudo_header = struct.pack("!4s4sBBH", source_address, target_address, 0, socket.IPPROTO_TCP, segment_length)
    tcp_checksum = calculateChecksum(pseudo_header + tcp_header + payload)

    return tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:] + payload

def buildIpv4Packet(source_address, target_address, tcp_segment):
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", IPV4_VERSION_AND_HEADER_LENGTH, 0,
        IPV4_HEADER_LENGTH + len(tcp_segment), IPV4_IDENTIFIER, 0,
        IPV4_TTL, socket.IPPROTO_TCP, 0, source_address, target_address,
    )
    ip_checksum = calculateChecksum(ip_header)

    return ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:] + tcp_segment

def buildTcpFrame(source_mac, source_ip, target_ip, source_port, target_port, sequence, acknowledgment, flags, payload=b""):
    source_address = socket.inet_aton(str(source_ip))
    target_address = socket.inet_aton(str(target_ip))
    tcp_segment = buildTcpSegment(source_address, target_address, source_port, target_port, sequence, acknowledgment, flags, payload)
    internet_packet = buildIpv4Packet(source_address, target_address, tcp_segment)
    ethernet_header = BROADCAST_ADDRESS + source_mac + struct.pack("!H", ETHERTYPE_IPV4)

    return ethernet_header + internet_packet

def buildSessionSegments(exchanges):
    yield True, TCP_SYN, CLIENT_SEQUENCE, 0, b""
    yield False, TCP_SYN | TCP_ACK, SERVER_SEQUENCE, CLIENT_SEQUENCE + 1, b""
    yield True, TCP_ACK, CLIENT_SEQUENCE + 1, SERVER_SEQUENCE + 1, b""
    client_sequence = CLIENT_SEQUENCE + 1
    server_sequence = SERVER_SEQUENCE + 1
    for from_client, payload in exchanges:
        if from_client:
            yield True, TCP_PUSH | TCP_ACK, client_sequence, server_sequence, payload
            client_sequence += len(payload)
            yield False, TCP_ACK, server_sequence, client_sequence, b""
        else:
            yield False, TCP_PUSH | TCP_ACK, server_sequence, client_sequence, payload
            server_sequence += len(payload)
            yield True, TCP_ACK, client_sequence, server_sequence, b""

    yield True, TCP_FIN | TCP_ACK, client_sequence, server_sequence, b""
    yield False, TCP_FIN | TCP_ACK, server_sequence, client_sequence + 1, b""
    yield True, TCP_ACK, client_sequence + 1, server_sequence + 1, b""

def buildSessionFrames(source_mac, source_ip, target_ip, source_port, target_port, exchanges):
    for from_client, flags, sequence, acknowledgment, payload in buildSessionSegments(exchanges):
        if from_client:
            yield buildTcpFrame(source_mac, source_ip, target_ip, source_port, target_port, sequence, acknowledgment, flags, payload)
        else:
            yield buildTcpFrame(source_mac, target_ip, source_ip, target_port, source_port, sequence, acknowledgment, flags, payload)

def buildHttpExchanges(target_ip, method, path, headers, body, response_body):
    request_lines = [f"{method} {path} HTTP/1.1", f"Host: {target_ip}", "Connection: close"]
    request_lines.extend(f"{name}: {value}" for name, value in headers)
    request_lines.append(f"Content-Length: {len(body)}")
    request = "\r\n".join(request_lines).encode("ascii") + b"\r\n\r\n" + body
    response = (
        f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(response_body)}\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + response_body

    return ((True, request), (False, response))

def buildProbeFrames(source_mac, source_ip, target_ip, source_port, selected_probe):
    if selected_probe in ("all", "ftp-cwd"):
        capture_frame = buildTcpFrame(
            source_mac, source_ip, target_ip, CAPTURE_SOURCE_PORT, FTP_PORT,
            CLIENT_SEQUENCE, 0, TCP_PUSH | TCP_ACK, FTP_COMMAND,
        )
        session_frames = buildSessionFrames(source_mac, source_ip, target_ip, source_port, FTP_PORT, FTP_EXCHANGES)
        yield "ftp-cwd", (capture_frame, *session_frames)

    for probe_index, (name, method, path, headers, body, response_body) in enumerate(HTTP_PROBES, start=1):
        if selected_probe not in ("all", name):
            continue

        exchanges = buildHttpExchanges(target_ip, method, path, headers, body, response_body)
        frames = buildSessionFrames(source_mac, source_ip, target_ip, source_port + probe_index, HTTP_PORT, exchanges)
        yield name, tuple(frames)

def sendProbeFrames(arguments):
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_IPV4)) as packet_socket:
        packet_socket.bind((arguments.iface, 0))
        interface_address = packet_socket.getsockname()
        if interface_address[3] != ETHERNET_HARDWARE_TYPE:
            raise ValueError("The selected interface must be an Ethernet interface.")

        source_mac = interface_address[4]
        source_port = random.randint(*SOURCE_PORT_RANGE)
        probes = buildProbeFrames(source_mac, arguments.source, arguments.target, source_port, arguments.case)
        for name, frames in probes:
            for frame in frames:
                sent_length = packet_socket.send(frame)
                if sent_length != len(frame):
                    raise OSError("The complete Ethernet frame could not be sent.")
                time.sleep(PACKET_INTERVAL_SECONDS)

            print(f"{name}: {len(frames)} packets sent", flush=True)

def runPacketProbes():
    parser = argparse.ArgumentParser(description="Send packet probes through an Ethernet interface.")
    parser.add_argument("-i", "--iface", required=True, help="Ethernet interface")
    parser.add_argument("-s", "--source", required=True, type=ipaddress.IPv4Address, help="Source IPv4 address")
    parser.add_argument("-t", "--target", required=True, type=ipaddress.IPv4Address, help="Destination IPv4 address")
    parser.add_argument("--case", choices=("all", *PROBE_NAMES), default="all", help="Probe selection")
    arguments = parser.parse_args()
    if not hasattr(socket, "AF_PACKET"):
        parser.error("Linux with AF_PACKET support is required.")
    if arguments.source == arguments.target:
        parser.error("Source and destination IPv4 addresses must differ.")

    try:
        sendProbeFrames(arguments)
    except PermissionError:
        parser.exit(1, "Raw packet access requires root or CAP_NET_RAW.\n")
    except (OSError, ValueError) as error:
        parser.exit(1, f"Packet sending failed: {error}\n")

if __name__ == "__main__":
    runPacketProbes()
