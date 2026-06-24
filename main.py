import socket
import struct
import textwrap
import os

def main():
    capture_l2 = True
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        print("Listening on AF_PACKET (Linux mode, Layer 2+)...")
    except AttributeError:
        capture_l2 = False
        HOST_IP = socket.gethostbyname(socket.gethostname())
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind((HOST_IP, 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == 'nt':
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print(f"Listening on {HOST_IP} (Windows mode)...")
        else:
            print(f"Listening on {HOST_IP} (macOS mode - restricted capture)...")

    print("\nSniffer is running. Filtering for DNS Traffic (Port 53)...")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            raw_data, addr = conn.recvfrom(65535)
            
            if capture_l2:
                dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            else:
                eth_proto = 0x0800
                data = raw_data
                
            if eth_proto == 0x0800 or eth_proto == 8:
                try:
                    (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
                 
                    if proto == 1:
                        icmp_type, code, checksum, data = icmp_packet(data)

                    elif proto == 6:
                        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)

                    elif proto == 17:
                        src_port, dest_port, length, data = udp_segment(data)

                        if src_port == 53 or dest_port == 53:
                            print('\n' + '='*50)
                            print(f'  - IPv4 Packet: Source: {src}, Target: {target}, Protocol: {proto}, TTL: {ttl}')
                            print(f'    - DNS Traffic (UDP): Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                            
                            if len(data) > 0:
                                print(f'      - Raw Hex:\n{format_multi_line("        ", data)}')
                                print(f'      - Readable Text:\n{format_readable_text("        ", data)}')

                    else:
                        pass
                
                except struct.error:
                    pass
                
                except struct.error:
                    pass
    
    except KeyboardInterrupt:
        print("\nSniffing stopped.")
        if os.name == 'nt' and not capture_l2:
            conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

def ethernet_frame(data):
    """Unpacks the 14-byte Ethernet frame."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), proto, data[14:]

def get_mac_addr(bytes_addr):
    """Converts raw bytes to a human-readable MAC address."""
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    """Unpacks the IPv4 header."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4    
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    """Converts raw bytes to a human-readable IP address."""
    return '.'.join(map(str, addr))

def icmp_packet(data):
    """Unpacks an ICMP (Ping) packet."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    """Unpacks a TCP segment."""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4    
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    """Unpacks a UDP segment."""
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_readable_text(prefix, payload, size=80):
    """Extracts and formats only the readable keyboard characters from the raw payload."""
    size -= len(prefix)
    readable_string = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)
    return '\n'.join([prefix + line for line in textwrap.wrap(readable_string, size)])

def format_multi_line(prefix, string, size=80):
    """Formats raw payload data for readable terminal output."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == '__main__':
    main()