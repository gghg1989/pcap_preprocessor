import numpy as np
import csv

import sys
import os
import os.path as path

def load_devices_list(path):
    device_info = {}

    with open(path) as devices_list_file:
        reader = csv.DictReader(devices_list_file)
        for row in reader:
            device_info[row['mac']] = row
    devices_list_file.close()

    return device_info

def tcp_extractor(file_name, input_dir, output_dir):
    global g_device_info

    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)
    
    output_path = output_dir + file_name

    # Add data header and init csv file
    output_csv_header = ['pid', 'timestamp', 'size', 'data_length', 'identification', 'fragment_offset',
        'ttl', 'header_checksum', 'direction', 'local_mac', 'remote_mac', 'local_ip', 'remote_ip',
        'local_port', 'remote_port', 'data_checksum', 'seq', 'ack', 'flags', 'win', 'groundtruth']
    with open(output_path, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=output_csv_header)
        writer.writeheader()
    csvfile.close()

    input_file_path = input_dir + file_name

    with open(output_path, 'a') as output_csv_file:
        writer = csv.writer(output_csv_file)
        
        with open(input_file_path) as input_csv_file:
            reader = csv.DictReader(input_csv_file)
            for row in reader:

                # Extract only the tcp protocal
                if row['protocal'] == '6':
                    #  Skip the internal
                    if row['direction'] != 'internal':
                        tcp = {}
                        new_stream = True

                        #  Change to local and remote depends on in or out direction
                        if row['direction'] == 'in':
                            tcp['local_mac'] = row['dst_mac']
                            tcp['remote_mac'] = row['src_mac']
                            tcp['local_ip'] = row['dst_ip']
                            tcp['remote_ip'] = row['src_ip']
                            tcp['local_port'] = row['dst_port']
                            tcp['remote_port'] = row['src_port']
                        if row['direction'] == 'out':
                            tcp['local_mac'] = row['src_mac']
                            tcp['remote_mac'] = row['dst_mac']
                            tcp['local_ip'] = row['src_ip']
                            tcp['remote_ip'] = row['dst_ip']
                            tcp['local_port'] = row['src_port']
                            tcp['remote_port'] = row['dst_port']

                        if tcp['local_mac'] in g_device_info:
                            groundtruth = g_device_info[tcp['local_mac']]['id']
                        else:
                            # if mac address is not in devices list, set groundtruth to 0 aka 'unknow'
                            groundtruth = 0

                        writer.writerow(
                            [row['pid'], row['timestamp'], row['size'], row['data_length'], row['identification'],
                            row['fragment_offset'],
                            row['ttl'], row['header_checksum'], row['direction'], tcp['local_mac'], tcp['remote_mac'],
                            tcp['local_ip'],
                            tcp['remote_ip'], tcp['local_port'], tcp['remote_port'], row['data_checksum'],
                            row['tcp_seq'], row['tcp_ack'],
                            row['tcp_flags'], row['tcp_win'], groundtruth])

        input_csv_file.close()
    output_csv_file.close()
    
    print('File ' + file_name + ' extraction is completed!')


def main(argv):
    global g_device_info

    workspace = 'data/'

    dataset_name = 'unsw'

    # Load device list from file
    devices_list_path = workspace + dataset_name + '/cps_devices_list.csv'
    g_device_info = load_devices_list(devices_list_path)

    input_dir = workspace + dataset_name + '/parsed_pcap/'
    
    output_dir = workspace + dataset_name + '/extracted_tcp/'

    # Iterate directory of input files
    input_files_dir = os.listdir(input_dir)
    for f in input_files_dir:
        parsed_pcap_file_name = f
        if not parsed_pcap_file_name.endswith('.csv'):
            print(parsed_pcap_file_name + "is not a csv file. Skipped.")
            continue
        # Extract tcp packet from parsed pcap file
        print("Start extracting: " + parsed_pcap_file_name + "...")
        tcp_extractor(parsed_pcap_file_name, input_dir, output_dir)
    
    print('TCP packets extractions are completed for dataset: ' + dataset_name)

if __name__ == "__main__":
    main(sys.argv[1:])