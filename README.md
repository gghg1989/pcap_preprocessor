# Pcap Preprocessor

An open source toolkits library for preprocessing network traffic .pcap data.

## Pre-request Environment

### Environment Requirement

python3.7 or higher version is required.

### Setup Environment
1. Install virtual environment
```
pip install virtualenv
```

2. Create venv directory
```
python3 -m venv .venv
```

3. Activate virtual environment
```
source .venv/bin/activate
```

4. Install packages from requirements.txt
```
pip install -r requirements.txt
```

5. Deactivate virtual environment
```
deactivate
```

### Data Storage Convention

* data/<data_set_name>/
    * raw_pcap/
    * parsed_pcap/
    * extracted_tcp/
    * physical_features/
        * <data_set_name>_combined_physical_features.csv
    * physical_features_by_device/
    * features_by_device/
    * <data_set_name>_device_list.csv
    
### Data Preprocessing Pipeline

('->': input; '=>': output.)
1. raw_pcap/ -> **parser_pcap** => parsed_pcap/
2. parsed_pcap/ -> **extractor_tcp** => extracted_tcp/
3. extracted_tcp/ -> **extractor_physical_feature** => physical_features/