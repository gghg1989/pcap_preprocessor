import os
import numpy as np
import csv

import sys
import os.path as path

import dpkt
from dpkt.compat import compat_ord
import socket
import struct

'''
Warning! This is an one time generator, don't redo it on the same data setup.

Generate device list with ID into CSV file.

'''

'''
TODO
1. Add TCP/UDP/ALL packets counter (done)
2. Add multi files process functions (done)
3. Keep other Ethernet payload types packet (deprecated)
'''

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def ip_addr(ip_address):
    return socket.inet_ntoa(ip_address)

def parsePcap(file_path):
    global g_isUnsw

    packets = []

    counter = 0

    counters = {
        'total':0,
        hex(dpkt.ethernet.ETH_TYPE_IP):0,
        dpkt.ip.IP_PROTO_TCP:0,
        dpkt.ip.IP_PROTO_UDP:0,
        'ip_header_mismatch':0
    }

    file = open(file_path,'rb')
    reader = dpkt.pcapng.Reader(file) if g_isUnsw else dpkt.pcap.Reader(file)
    for ts, pkt in reader:

        # ts: timestamp
        # pkt: packet object
        '''
        'pid', 'timestamp', 'size', 'data_length', 'protocal', 
        'identification', 'fragment_offset', 'ttl', 'header_checksum',
        'direction', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
        'data_checksum', 'tcp_seq', 'tcp_ack', 'tcp_flags', 'tcp_win', 'udp_ulen'
        '''

        counter += 1
        counters['total'] += 1
        
        # Get packet object
        try:
            eth = dpkt.ethernet.Ethernet(pkt)
        except Exception:
            print('An error exist in current packet. Skip...')
            continue
        
        # Print all attributes of header
        # for att in dir(eth):
        #     print (att, getattr(eth, att))
        
        
        # Ethernet payload types - http://standards.ieee.org/regauth/ethertype
        # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/ethernet.html
        '''
        ETH_TYPE_EDP = 0x00bb  # Extreme Networks Discovery Protocol
        ETH_TYPE_PUP = 0x0200  # PUP protocol
        ETH_TYPE_IP = 0x0800  # IP protocol
        ETH_TYPE_ARP = 0x0806  # address resolution protocol
        ETH_TYPE_AOE = 0x88a2  # AoE protocol
        ETH_TYPE_CDP = 0x2000  # Cisco Discovery Protocol
        ETH_TYPE_DTP = 0x2004  # Cisco Dynamic Trunking Protocol
        ETH_TYPE_REVARP = 0x8035  # reverse addr resolution protocol
        ETH_TYPE_8021Q = 0x8100  # IEEE 802.1Q VLAN tagging
        ETH_TYPE_8021AD = 0x88a8  # IEEE 802.1ad
        ETH_TYPE_QINQ1 = 0x9100  # Legacy QinQ
        ETH_TYPE_QINQ2 = 0x9200  # Legacy QinQ
        ETH_TYPE_IPX = 0x8137  # Internetwork Packet Exchange
        ETH_TYPE_IP6 = 0x86DD  # IPv6 protocol
        ETH_TYPE_PPP = 0x880B  # PPP
        ETH_TYPE_MPLS = 0x8847  # MPLS
        ETH_TYPE_MPLS_MCAST = 0x8848  # MPLS Multicast
        ETH_TYPE_PPPoE_DISC = 0x8863  # PPP Over Ethernet Discovery Stage
        ETH_TYPE_PPPoE = 0x8864  # PPP Over Ethernet Session Stage
        ETH_TYPE_LLDP = 0x88CC  # Link Layer Discovery Protocol
        ETH_TYPE_TEB = 0x6558  # Transparent Ethernet Bridging
        '''
        # If packet is not ethernet packet, skip
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            if hex(eth.type) not in counters.keys():
                counters[hex(eth.type)] = 1
            else:
                counters[hex(eth.type)] += 1
            continue
        
        counters[hex(dpkt.ethernet.ETH_TYPE_IP)] += 1

        # Get packet object ip data 
        ip = eth.data
        
        # Print all attributes of packet data
        # for att in dir(ip):
        #     print (att, getattr(ip, att))
        
        # If packet doesn't have protocal type, skip
        if not hasattr(ip, 'p'):
            continue

        # Assign customized packet ID        
        pid = counter

        # Get time stamp
        timestamp = ts
        
        # Get entire packet size(header + data)
        size = ip.len

        # if not size - data_length == 14:
        #     counters['ip_header_mismatch'] += 0

        # Get packet protocal type
        protocal = ip.p
        protocal_name = ip.get_proto(ip.p).__name__

        # Get packet identification
        identification = ip.id

        # Get packet fragment offset
        fragment_offset = ip.off

        # Get packet IPv4 Time-to-live
        ttl = ip.ttl

        # Get header checksum
        header_checksum = ip.sum

        # Get MAC address of source and destination
        src_mac = mac_addr(eth.src)
        dst_mac = mac_addr(eth.dst)
        
        # Get source and destination ip
        src_ip = ip_addr(ip.src)
        dst_ip = ip_addr(ip.dst)

        if src_ip.startswith('192.168.') and dst_ip.startswith('192.168.'):
            direction = 'internal'
        elif src_ip.startswith('192.168.'):
            direction = 'out'
        elif dst_ip.startswith('192.168.'):
            direction = 'in'
        else:
            direction = None
        
        # Get packet data object if packet is TCP/UDP
        if hasattr(ip, 'data'):
            packet_data = ip.data

            # Check if port number of source and destination are exist
            if hasattr(packet_data, 'sport') or hasattr(packet_data, 'dport'):
                src_port = packet_data.sport
                dst_port = packet_data.dport
            else:
                src_port = None
                dst_port = None
            data_checksum = packet_data.sum if hasattr(packet_data, 'sum') else None

            data_length = len(packet_data.data) if hasattr(packet_data, 'data') else 0

            # If packet is TCP packet
            # Protocol (ip_p) - http://www.iana.org/assignments/protocol-numbers
            # https://dpkt.readthedocs.io/en/latest/_modules/dpkt/ip.html
            if protocal == dpkt.ip.IP_PROTO_TCP:
                tcp_seq = packet_data.seq
                tcp_ack = packet_data.ack
                tcp_flags = packet_data.flags
                tcp_win = packet_data.win
                udp_ulen = None
                counters[dpkt.ip.IP_PROTO_TCP] += 1

                
                # payload_length = len(packet_data)
                # print(pid)
                # print('data_length:' + str(data_length))
                # print('payload_length:' + str(payload_length))
                # print('tcp_header_length:' + str(payload_length - data_length))
                # print('data_length:' + str(data_length))
            elif protocal == dpkt.ip.IP_PROTO_UDP:
                tcp_seq = None
                tcp_ack = None
                tcp_flags = None
                tcp_win = None
                udp_ulen = packet_data.ulen if hasattr(packet_data, 'ulen') else None
                counters[dpkt.ip.IP_PROTO_UDP] += 1
            else:
                tcp_seq = None
                tcp_ack = None
                tcp_flags = None
                tcp_win = None
                udp_ulen = None
                if str(protocal) not in counters.keys():
                    counters[str(protocal)] = 1
                else:
                    counters[str(protocal)] += 1
        else:
            tcp_seq = None
            tcp_ack = None
            tcp_flags = None
            tcp_win = None
            udp_ulen = None
            continue

        packets.append([pid, timestamp, size, data_length, protocal, 
                        identification, fragment_offset, ttl, header_checksum,
                        direction, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port,
                        data_checksum, tcp_seq, tcp_ack, tcp_flags, tcp_win, udp_ulen])
        
        # print('pid: ' + str(pid) + ', ' 
        #     + 'timestamp: ' + str(timestamp) + ', ' 
        #     + 'size: ' + str(size) + ', ' 
        #     + 'data_length: ' + str(data_length) + ', ' 
        #     + 'protocal: ' + str(protocal) + ', ' 
        #     + 'identification: ' + str(identification) + ', ' 
        #     + 'fragment_offset: ' + str(fragment_offset) + ', ' 
        #     + 'ttl: ' + str(ttl) + ', ' 
        #     + 'header_checksum: ' + str(header_checksum) + ', '
        #     + 'direction: ' + str(direction) + ', ' 
        #     + 'src_mac: ' + str(src_mac) + ', ' 
        #     + 'dst_mac: ' + str(dst_mac) + ', ' 
        #     + 'src_ip: ' + str(src_ip) + ', ' 
        #     + 'dst_ip: ' + str(dst_ip) + ', ' 
        #     + 'src_port: ' + str(src_port) + ', ' 
        #     + 'dst_port: ' + str(dst_port) + ', '
        #     + 'data_checksum: ' + str(data_checksum) + ', ' 
        #     + 'tcp_seq: ' + str(tcp_seq) + ', ' 
        #     + 'tcp_ack: ' + str(tcp_ack) + ', ' 
        #     + 'tcp_flags: ' + str(tcp_flags) + ', ' 
        #     + 'tcp_win: ' + str(tcp_win) + ', ' 
        #     + 'udp_ulen: ' + str(udp_ulen)
        #     )
        
        # if counter >= 30:
        #     break

    for c in counters:
            print(str(c) + ': ' + str(counters[c]))
    return packets

def main(argv):
    # print ('Number of arguments:', len(argv), 'arguments.')
    # print ('Argument List:', str(argv))

    # The flag for dataset
    global g_isUnsw
    
    workspace = 'data/'

    dataset_name = 'unsw'

    if dataset_name == 'unsw':
        g_isUnsw = True
    else:
        g_isUnsw = False

    # Settings for output
    # The flag for if save the output to file
    flag_output_to_file = True

    # Location for output files !!! [WARNING: Modify before use]
    output_dir_path = workspace + dataset_name + '/parsed_pcap/'
    
    if not os.path.isdir(output_dir_path):
        os.mkdir(output_dir_path)

    # Iterate directory of pcap files for parsing
    # Location for input pcap files !!! [WARNING: Modify before use]
    pcap_files_dir_dir = workspace + dataset_name + '/raw_pcap/'
    pcap_files_dir = os.listdir(pcap_files_dir_dir)
    for f in pcap_files_dir:
        pcap_file_name = f
        if not pcap_file_name.endswith('.pcap'):
            print(pcap_file_name + " is not a pcap file. Skipped.")
            continue

        pcap_file_path = pcap_files_dir_dir + pcap_file_name
        # print(pcap_file_path)
        output_csv_path = output_dir_path + pcap_file_name.split('.')[0] + '.csv'
        # print(output_csv_path)

        if path.exists(output_csv_path):
            print(pcap_file_name + ' is already exist. Skip...')
            continue

        print("Start parsing: " + pcap_file_path + "...")

        packets = parsePcap(pcap_file_path)
        print('File ' + pcap_file_path + ' parsing complete!')

        if not flag_output_to_file:
            exit()

        print('Start saving packets data to csv file.')

        # Add data header and init csv file
        output_csv_header = ['pid', 'timestamp', 'size', 'data_length', 'protocal', 
                        'identification', 'fragment_offset', 'ttl', 'header_checksum',
                        'direction', 'src_mac', 'dst_mac', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                        'data_checksum', 'tcp_seq', 'tcp_ack', 'tcp_flags', 'tcp_win', 'udp_ulen']
        # if not path.exists(output_csv_path):
        with open(output_csv_path, 'a') as output_csv_file:
            writer = csv.DictWriter(output_csv_file, fieldnames=output_csv_header)
            writer.writeheader()
        output_csv_file.close()

        with open(output_csv_path, 'a') as output_csv_file:
            writer = csv.writer(output_csv_file)
            for p in packets:
                writer.writerow(p)

        output_csv_file.close()
        
        print(pcap_file_name + ' is saved.')

    print('All pcap files are parsed.')

if __name__ == "__main__":
    main(sys.argv[1:])