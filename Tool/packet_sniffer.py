"""Packet capture and packet decoding helpers for the IDS GUI.

This module is responsible only for reading live packets and converting them
into dictionaries that the GUI and ML predictor can understand. It does not
make attack decisions by itself.
"""

import socket
import struct
import time
import threading
import os
import subprocess
from datetime import datetime
from collections import deque, defaultdict
import pandas as pd
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
import warnings
warnings.filterwarnings("ignore")

class PacketSniffer:
    """Small wrapper around Scapy's sniff function.

    Packet capture runs in a background thread so the PyQt GUI remains
    responsive. New packets and capture errors are sent back through callbacks.
    """

    def __init__(self, interface=None):
        self.interface = interface
        self.is_sniffing = False
        self.sniffer_thread = None
        self.packets = deque(maxlen=10000)  # Keep last 10,000 packets
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'sources': defaultdict(int),
            'destinations': defaultdict(int),
            'start_time': None
        }
        self.packet_callbacks = []
        self.error_callbacks = []
        
    def add_packet_callback(self, callback):
        """Add callback function to be called when new packet arrives"""
        self.packet_callbacks.append(callback)
    
    def remove_packet_callback(self, callback):
        """Remove callback function"""
        if callback in self.packet_callbacks:
            self.packet_callbacks.remove(callback)

    def add_error_callback(self, callback):
        """Add callback function to be called when capture fails"""
        self.error_callbacks.append(callback)

    def _notify_error(self, message):
        for callback in self.error_callbacks:
            try:
                callback(message)
            except Exception as e:
                print(f"Error callback failed: {e}")
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        if not self.is_sniffing:
            return
            
        packet_info = self.extract_packet_info(packet)
        if packet_info:
            self.packets.append(packet_info)
            self.stats['total_packets'] += 1
            
            # Update statistics
            self.stats['protocols'][packet_info['protocol']] += 1
            self.stats['sources'][packet_info['source']] += 1
            self.stats['destinations'][packet_info['destination']] += 1
            
            # Notify all callbacks (for GUI updates)
            for callback in self.packet_callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    print(f"Callback error: {e}")
    
    def extract_packet_info(self, packet):
        """Extract display and ML fields from one Scapy packet."""
        try:
            original_packet = packet
            packet = self.normalize_packet(packet)
            packet_info = {
                'timestamp': datetime.now(),
                'time_str': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'source': 'Unknown',
                'destination': 'Unknown',
                'protocol': 'Unknown',
                'length': len(original_packet),
                'info': '',
                'hex_data': '',
                'raw_packet': original_packet
            }
            
            # Ethernet layer
            if Ether in packet:
                packet_info['src_mac'] = packet[Ether].src
                packet_info['dst_mac'] = packet[Ether].dst
            
            # IP layer
            if IP in packet:
                packet_info['source'] = packet[IP].src
                packet_info['destination'] = packet[IP].dst
                packet_info['protocol'] = self.get_protocol_name(packet[IP].proto)
                
                # TCP
                if TCP in packet:
                    tcp = packet[TCP]
                    tcp_flags = self.get_tcp_flags(tcp.flags)
                    packet_info['info'] = f"TCP {packet_info['source']}:{tcp.sport} -> {packet_info['destination']}:{tcp.dport} "
                    packet_info['info'] += f"Flags: {tcp_flags} Seq: {tcp.seq} Ack: {tcp.ack}"
                    packet_info['sport'] = tcp.sport
                    packet_info['dport'] = tcp.dport
                    packet_info['flags'] = tcp_flags
                    
                # UDP
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info['info'] = f"UDP {packet_info['source']}:{udp.sport} -> {packet_info['destination']}:{udp.dport}"
                    packet_info['sport'] = udp.sport
                    packet_info['dport'] = udp.dport
                    
                # ICMP
                elif ICMP in packet:
                    icmp = packet[ICMP]
                    packet_info['info'] = f"ICMP {packet_info['source']} -> {packet_info['destination']} Type: {icmp.type}"

            # IPv6 layer
            elif IPv6 in packet:
                ipv6 = packet[IPv6]
                packet_info['source'] = ipv6.src
                packet_info['destination'] = ipv6.dst
                packet_info['protocol'] = self.get_protocol_name(ipv6.nh)

                # TCP over IPv6
                if TCP in packet:
                    tcp = packet[TCP]
                    tcp_flags = self.get_tcp_flags(tcp.flags)
                    packet_info['info'] = f"TCP6 {packet_info['source']}:{tcp.sport} -> {packet_info['destination']}:{tcp.dport} "
                    packet_info['info'] += f"Flags: {tcp_flags} Seq: {tcp.seq} Ack: {tcp.ack}"
                    packet_info['sport'] = tcp.sport
                    packet_info['dport'] = tcp.dport
                    packet_info['flags'] = tcp_flags

                # UDP over IPv6
                elif UDP in packet:
                    udp = packet[UDP]
                    packet_info['info'] = f"UDP6 {packet_info['source']}:{udp.sport} -> {packet_info['destination']}:{udp.dport}"
                    packet_info['sport'] = udp.sport
                    packet_info['dport'] = udp.dport

                # ICMPv6
                elif ipv6.nh == 58:
                    packet_info['info'] = f"ICMPv6 {packet_info['source']} -> {packet_info['destination']}"
                    
            # ARP packets
            elif ARP in packet:
                arp = packet[ARP]
                packet_info['source'] = arp.psrc
                packet_info['destination'] = arp.pdst
                packet_info['protocol'] = 'ARP'
                packet_info['info'] = f"ARP {arp.op} {arp.psrc} -> {arp.pdst}"
            
            # Get hex data (first 64 bytes)
            packet_info['hex_data'] = self.get_hex_dump(packet)
            
            return packet_info
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None

    def normalize_packet(self, packet):
        """Decode packets that Scapy leaves as raw payloads.

        On macOS, packet capture uses BPF devices. Depending on the interface,
        Scapy may not immediately expose IP/IPv6/ARP layers, so we try the
        common offsets before giving up and displaying the packet as Unknown.
        """
        if IP in packet or IPv6 in packet or ARP in packet:
            return packet

        try:
            raw_data = bytes(packet)
        except Exception:
            return packet

        candidates = [raw_data]
        if len(raw_data) > 4:
            candidates.append(raw_data[4:])   # BSD loopback/null header
        if len(raw_data) > 14:
            candidates.append(raw_data[14:])  # Ethernet payload

        for payload in candidates:
            if not payload:
                continue

            version = payload[0] >> 4
            try:
                if version == 4:
                    return IP(payload)
                if version == 6:
                    return IPv6(payload)
            except Exception:
                continue

        return packet
    
    def get_protocol_name(self, proto_num):
        """Convert protocol number to name"""
        protocol_names = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            2: 'IGMP',
            41: 'IPv6',
            58: 'ICMPv6',
            89: 'OSPF'
        }
        return protocol_names.get(proto_num, f'Proto_{proto_num}')
    
    def get_tcp_flags(self, flags):
        """Convert TCP flags to string representation"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return '/'.join(flag_names) if flag_names else 'None'
    
    def get_hex_dump(self, packet, max_bytes=64):
        """Create hex dump of packet data"""
        try:
            raw_data = bytes(packet)
            hex_str = ' '.join(f'{b:02x}' for b in raw_data[:max_bytes])
            if len(raw_data) > max_bytes:
                hex_str += ' ...'
            return hex_str
        except:
            return ''
    
    def start_sniffing(self, filter_str=None, count=0):
        """Start packet sniffing"""
        if self.is_sniffing:
            return False
            
        self.is_sniffing = True
        self.stats['start_time'] = datetime.now()
        
        def sniff_thread():
            try:
                # Scapy requires root/admin privileges for live capture on most
                # systems. Permission errors are forwarded to the GUI via
                # _notify_error instead of being hidden in the terminal.
                sniff(
                    prn=self.packet_handler,
                    filter=filter_str,
                    count=count,
                    iface=self.interface,
                    store=0
                )
            except Exception as e:
                message = f"Sniffing error on {self.interface or 'default interface'}: {e}"
                print(message)
                self._notify_error(message)
            finally:
                self.is_sniffing = False
        
        self.sniffer_thread = threading.Thread(target=sniff_thread, daemon=True)
        self.sniffer_thread.start()
        return True
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.is_sniffing = False
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            # Scapy doesn't have a clean way to stop sniffing, so we use a flag
            pass
    
    def get_recent_packets(self, count=100):
        """Get most recent packets"""
        return list(self.packets)[-count:]
    
    def get_statistics(self):
        """Get current statistics"""
        stats = self.stats.copy()
        if stats['start_time']:
            stats['duration'] = datetime.now() - stats['start_time']
        return stats
    
    def clear_packets(self):
        """Clear captured packets"""
        self.packets.clear()
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'sources': defaultdict(int),
            'destinations': defaultdict(int),
            'start_time': self.stats['start_time']
        }
    
    def save_packets_to_file(self, filename, format='csv'):
        """Save captured packets to file"""
        try:
            if format.lower() == 'csv':
                df = pd.DataFrame(self.packets)
                # Remove raw_packet column as it's not serializable
                if 'raw_packet' in df.columns:
                    df = df.drop('raw_packet', axis=1)
                df.to_csv(filename, index=False)
            elif format.lower() == 'pcap':
                wrpcap(filename, [p['raw_packet'] for p in self.packets if 'raw_packet' in p])
            return True
        except Exception as e:
            print(f"Error saving packets: {e}")
            return False

# Utility function to get available network interfaces
def get_network_interfaces():
    """Get list of available network interfaces"""
    if os.name == 'nt':
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = get_windows_if_list()
            return [iface['name'] for iface in interfaces]
        except Exception:
            return ['Ethernet', 'Wi-Fi']  # Fallback

    try:
        interfaces = [iface for iface in get_if_list() if iface != 'lo']
    except Exception:
        return ['en0', 'en1', 'Wi-Fi']

    def interface_score(iface):
        score = 0
        # Prefer active interfaces with an IPv4 address because those are the
        # most likely to show useful demo traffic on macOS laptops.
        try:
            result = subprocess.run(
                ["ifconfig", iface],
                capture_output=True,
                text=True,
                timeout=1,
                check=False,
            )
            output = result.stdout.lower()
            if "status: active" in output:
                score += 100
            if "inet " in output:
                score += 40
            if "status: inactive" in output:
                score -= 100
        except Exception:
            pass

        if iface.startswith("en"):
            score += 20
        if iface == "lo0":
            score -= 50
        if iface.startswith(("anpi", "utun", "awdl", "llw", "bridge", "gif", "stf")):
            score -= 20
        return (-score, iface)

    return sorted(interfaces, key=interface_score)

if __name__ == "__main__":
    # Test the sniffer
    sniffer = PacketSniffer()
    print("Available interfaces:", get_network_interfaces())
    
    def print_packet(packet):
        print(f"{packet['time_str']} {packet['protocol']} {packet['source']} -> {packet['destination']} {packet['info']}")
    
    sniffer.add_packet_callback(print_packet)
    print("Starting sniffer for 10 packets...")
    sniffer.start_sniffing(count=10)
    
    # Wait for completion
    time.sleep(15)
    sniffer.stop_sniffing()
