import numpy as np
import csv

import sys
import os
import os.path as path
import pandas as pd

def assign_streamid(file_name, input_dir, output_dir):
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)
    
    output_path = output_dir + file_name.split('.')[0] + '_by_session.csv'

    # Init stream ID counter
    stream_id_counter = 0

    # Init stream ID dictionary
    stream_dict = {}

    # Init output file with header
    myFields = ['pid', 'timestamp', 'size', 'data_length', 'identification', 'fragment_offset',
        'ttl', 'header_checksum', 'direction', 'local_mac', 'remote_mac', 'local_ip', 'remote_ip',
        'local_port', 'remote_port', 'data_checksum', 'seq', 'ack', 'flags', 'win',
        'stream_id', 'groundtruth']
    with open(output_path, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=myFields)
        writer.writeheader()
    csvfile.close()

    input_file_path = input_dir + file_name

    with open(output_path, 'a') as output_csv_file:
        writer = csv.writer(output_csv_file)

        with open(input_file_path) as input_csv_file:
            reader = csv.DictReader(input_csv_file)

            for row in reader:
                
                tcp_four_tuple = row['local_ip'] + '_' + row['local_port'] + '_' + row['remote_ip'] + '_' + row['remote_port']

                if tcp_four_tuple not in stream_dict:
                    stream_id_counter += 1
                    stream_dict[tcp_four_tuple] = stream_id_counter
            
                stream_id = stream_dict[tcp_four_tuple]
                
                # print(str(stream_id_counter) + ' : ' + str(stream_dict[tcp_four_tuple]))

                writer.writerow(
                    [row['pid'], row['timestamp'], row['size'], row['data_length'], row['identification'], row['fragment_offset'],
                     row['ttl'], row['header_checksum'], row['direction'], row['local_mac'], row['remote_mac'],
                     row['local_ip'], row['remote_ip'], row['local_port'], row['remote_port'], row['data_checksum'],
                     row['seq'], row['ack'], row['flags'], row['win'], stream_id, row['groundtruth']])
        
        input_csv_file.close()
    output_csv_file.close()

    print('Stream ID are assigned for ' + file_name)


def main(argv):
    workspace = ''

    dataset_name = 'unsw'

    slicing_method = 'by_session' # by_session/by_60s

    input_dir = workspace + 'data/extracted_tcp/' + dataset_name + '/'
    
    output_dir = workspace + 'data/tcp_with_streamID/' + slicing_method + '/' + dataset_name + '/'

    # Iterate directory of input files
    input_files_dir = os.listdir(input_dir)
    for f in input_files_dir:
        tcp_file_name = f
        # Check file type by extension
        if not tcp_file_name.endswith('.csv'):
            print(tcp_file_name + "is not a csv file. Skipped.")
            continue
        
        # Assign stream ID for tcp data
        print("Start assigning stream ID for: " + tcp_file_name + "...")
        assign_streamid(tcp_file_name, input_dir, output_dir)

    print('Stream ID are assigned for dataset: ' + dataset_name)


if __name__ == "__main__":
    main(sys.argv[1:])