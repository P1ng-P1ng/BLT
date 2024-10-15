#!/usr/bin/env python3

import argparse
from scapy.all import rdpcap, IP, TCP, UDP
import sys
from collections import defaultdict

PORT_TO_APPLICATION = {
    20: 'FTP (Data)',
    21: 'FTP (Control)',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    # Add more mappings as needed
}

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Wireshark PCAP Analyzer with Filtering, Detailed Flows, and Application Identification'
    )
    parser.add_argument('pcap_file', help='Path to the PCAP file to analyze')

    parser.add_argument('--ip', action='store_true', help='List all unique IP addresses found in the PCAP')
    parser.add_argument('--ports', action='store_true', help='List all unique source and destination ports in the PCAP')
    parser.add_argument('--flows', action='store_true', help='Display all unique connections between source and destination IPs with ports and applications')

    parser.add_argument('--src-ip', help='Filter for packets originating from a specific source IP')
    parser.add_argument('--dst-ip', help='Filter for packets destined to a specific destination IP')
    parser.add_argument('--src-port', type=int, help='Filter for packets originating from a specific source port')
    parser.add_argument('--dst-port', type=int, help='Filter for packets destined to a specific destination port')

    return parser.parse_args()

def apply_filters(packets, src_ip=None, dst_ip=None, src_port=None, dst_port=None):
    filtered_packets = []
    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            if src_ip and ip_layer.src != src_ip:
                continue
            if dst_ip and ip_layer.dst != dst_ip:
                continue
            transport = None
            if TCP in pkt:
                transport = pkt[TCP]
            elif UDP in pkt:
                transport = pkt[UDP]
            if transport:
                if src_port and transport.sport != src_port:
                    continue
                if dst_port and transport.dport != dst_port:
                    continue
            filtered_packets.append(pkt)
        else:
            continue
    return filtered_packets

def list_unique_ips(packets):
    ip_set = set()
    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            ip_set.add(ip_layer.src)
            ip_set.add(ip_layer.dst)
    print("\nUnique IP Addresses:")
    for ip in sorted(ip_set):
        print(ip)

def list_unique_ports(packets):
    src_ports = set()
    dst_ports = set()
    for pkt in packets:
        if TCP in pkt or UDP in pkt:
            transport = pkt[TCP] if TCP in pkt else pkt[UDP]
            src_ports.add(transport.sport)
            dst_ports.add(transport.dport)
    print("\nUnique Source Ports:")
    for port in sorted(src_ports):
        print(port)
    print("\nUnique Destination Ports:")
    for port in sorted(dst_ports):
        print(port)

def get_application(port):
    return PORT_TO_APPLICATION.get(port, 'Unknown')

def display_flows(packets):
    flows = defaultdict(int)
    for pkt in packets:
        if IP in pkt:
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = None
            dst_port = None
            application_src = 'Unknown'
            application_dst = 'Unknown'
            if TCP in pkt:
                transport = pkt[TCP]
                src_port = transport.sport
                dst_port = transport.dport
            elif UDP in pkt:
                transport = pkt[UDP]
                src_port = transport.sport
                dst_port = transport.dport
            else:
                src_port = '-'
                dst_port = '-'

            if isinstance(src_port, int):
                application_src = get_application(src_port)
            if isinstance(dst_port, int):
                application_dst = get_application(dst_port)

            flow = ((src_ip, src_port, application_src), (dst_ip, dst_port, application_dst))
            flows[flow] += 1
    print("\nUnique Flows (Source IP:Port [App] -> Destination IP:Port [App] : Number of Packets):")
    sorted_flows = sorted(flows.items(), key=lambda item: item[1], reverse=True)
    for flow, count in sorted_flows:
        (src_ip, src_port, app_src), (dst_ip, dst_port, app_dst) = flow
        src_port_display = src_port if src_port != '-' else '-'
        dst_port_display = dst_port if dst_port != '-' else '-'
        print(f"{src_ip}:{src_port_display} [{app_src}] -> {dst_ip}:{dst_port_display} [{app_dst}] : {count} packets")

def main():
    args = parse_arguments()
    try:
        print(f"Reading PCAP file: {args.pcap_file}...")
        packets = rdpcap(args.pcap_file)
        print(f"Total packets read: {len(packets)}")
    except FileNotFoundError:
        print(f"Error: File '{args.pcap_file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        sys.exit(1)

    original_packet_count = len(packets)
    packets = apply_filters(
        packets,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port
    )
    filtered_packet_count = len(packets)
    if any([args.src_ip, args.dst_ip, args.src_port, args.dst_port]):
        print(f"Filtered packets: {filtered_packet_count} (from {original_packet_count})")

    if not (args.ip or args.ports or args.flows):
        args.ip = True
        args.ports = True
        args.flows = True

    if args.ip:
        list_unique_ips(packets)
    if args.ports:
        list_unique_ports(packets)
    if args.flows:
        display_flows(packets)

    if not (args.ip or args.ports or args.flows):
        print("No analysis option selected. Use --ip, --ports, and/or --flows.")
        sys.exit(1)

if __name__ == '__main__':
    main()
