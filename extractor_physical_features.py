import sys
import os
import pandas as pd



def physical_features_extractor(file_name, input_dir, output_dir):
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)
    
    output_path = output_dir + file_name
    
    input_file_path = input_dir + file_name
    
    df = pd.read_csv(input_file_path)
    '''
    0'pid', 1'timestamp', 2'size', 3'data_length', 4'identification', 5'fragment_offset',
    6'ttl', 7'header_checksum', 8'direction', 9'local_mac', 10'remote_mac', 11'local_ip', 12'remote_ip',
    13'local_port', 14'remote_port', 15'data_checksum', 16'seq', 17'ack', 18'flags', 19'win', 20'groundtruth'
    '''
    df.iloc[:, [1, 2, 3, 6, 8, 11, 12, 13, 14, 19, 20]].to_csv(output_path, index= None, header = True)
    
def insert_header_length(file_name,  output_dir): 
    if not os.path.isdir(output_dir):
        os.mkdir(output_dir)
    
    input_file_path = output_dir + file_name
    
    df = pd.read_csv(input_file_path)

    df.insert(3,'header_length',df['size'] - df['data_length'])
    
    df.to_csv(input_file_path, index= None, header = True)
    
    




def main(argv):
    workspace = 'data/'

    dataset_name = 'unsw'

    input_dir = workspace + dataset_name + '/extracted_tcp/'

    output_dir = workspace + dataset_name + '/physical_features/' 
    
    # Iterate directory of input files
    input_files_dir = os.listdir(input_dir)
    for f in input_files_dir:
        extracted_tcp_file_name = f
        if not extracted_tcp_file_name.endswith('.csv'):
            print(extracted_tcp_file_name + "is not a csv file. Skipped.")
            continue
        # Extract tcp packet from parsed pcap file
        print("Start extracting: " + extracted_tcp_file_name + "...")
        physical_features_extractor(extracted_tcp_file_name, input_dir, output_dir)
        insert_header_length(extracted_tcp_file_name, output_dir)
    
    print('physical features extractions are completed for dataset: ' + dataset_name)

    
if __name__ == "__main__":
    main(sys.argv[1:])