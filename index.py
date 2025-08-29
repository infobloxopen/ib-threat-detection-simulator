#!/usr/bin/env python3
# This script processes large compressed JSON threat intelligence files to extract recent, actionable threats.

# What it does:

# Loads a gzipped JSON file containing cybersecurity threat data
# Filters by expiration date to keep only threats that don't expire for 30+ days
# Sorts results by import date (newest first)
# Exports two files:
# sorted_[filename].ndjson - Filtered records with indicator and property only, one per line
# sorted_[filename].csv - Summary with 2 key columns: indicator, property
# Purpose: Extract threat intelligence with long-term validity, making it ideal for security operations that need actionable data.

# Usage:
# The script can download from S3 using bucket/key or use a specific filename
# Default: bucket="rpz-zones-useast", key="cacheFiles/infoblox-base.json.gz"
# Command to run with defaults to S3 location (rpz-zones-useast/cacheFiles/infoblox-base.json.gz): python3 index.py
# Command to run with S3 params (provide bucket name and object key):   python3 index.py rpz-zones-useast cacheFiles/infoblox-base.json.gz
# Command to run with specific filename:  python3 index.py infoblox-base.json.gz

import json
import gzip
import csv
import sys
import boto3
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Categories mapping for threat intelligence classification
categories = {
    "Phishing": ["phishing_generic", "phishing_smishing", "phishing_phish"],
    "Lookalikes": ["suspicious_lookalike"],
    "TDS": ["Malicious_TDS", "suspicious_TDS"],
    "Command_&_Control": ["MalwareC2_Generic", "MalwareC2DGA_Generic"],
    "DGAS_&_RDGAS": ["suspicious_dga", "suspicious_rdga", "malicious_rdga"],
    "Emerging_Domains": ["suspicious_emergentdomain"],
    "High_Risk": ["suspicious_generic", "suspicious_nameserver"],
    "Malicious_Domains": ["malicious_generic", "malwaredownload_generic"]
}

def download_from_s3(bucket: str, key: str, local_filename: str) -> str:
    """Download file from S3 bucket/key to local filesystem"""
    print(f"Downloading from S3: {bucket}/{key}")
    
    s3_client = boto3.client('s3')
    try:
        s3_client.download_file(bucket, key, local_filename)
        print(f"Downloaded to: {local_filename}")
        return local_filename
    except Exception as e:
        print(f"Error downloading from S3: {e}")
        raise

class ThreatFilter:
    """Process large gzipped JSON files containing threat data"""
    
    def __init__(self, expiration_days=30):
        self.expiration_cutoff = datetime.now() + timedelta(days=expiration_days)
        print(f"Filtering: expiration > {self.expiration_cutoff.date()}")
    
    def parse_date(self, date_str: str) -> datetime:
        """Parse ISO date string, return datetime.min if invalid"""
        if not date_str:
            return datetime.min
        try:
            date_str = date_str.rstrip('Z')
            for fmt in ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]:
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
        except:
            pass
        return datetime.min
    
    def process_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Process JSON.gz file with expiration filtering"""
        print(f"Processing: {file_path}")
        
        with gzip.open(file_path, 'rt', encoding='utf-8') as f:
            data = json.load(f)
            threats = data.get('Threats', [])
            
        print(f"Total threats: {len(threats)}")
        
        # Filter by expiration date only
        filtered_threats = [
            t for t in threats 
            if self.parse_date(t.get('expiration')) > self.expiration_cutoff
        ]
        print(f"After expiration filter: {len(filtered_threats)}")
        
        return filtered_threats
    
    def sort_and_save(self, threats: List[Dict[str, Any]], base_name: str):
        """Sort by imported date and save as NDJSON and CSV"""
        # Sort by imported date (latest first)
        sorted_threats = sorted(
            threats,
            key=lambda t: self.parse_date(t.get('imported')),
            reverse=True
        )
        
        print(f"Sorted {len(sorted_threats)} records by imported date")
        
        # Save NDJSON (filtered to indicator and property only)
        ndjson_file = f"sorted_{base_name}.ndjson"
        with open(ndjson_file, 'w', encoding='utf-8') as f:
            for threat in sorted_threats:
                filtered_threat = {
                    'indicator': threat.get('indicator', ''),
                    'property': threat.get('property', '')
                }
                f.write(json.dumps(filtered_threat) + '\n')
        print(f"Saved NDJSON: {ndjson_file}")
        
        # Save CSV
        csv_file = f"sorted_{base_name}.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['indicator', 'property'])
            for threat in sorted_threats:
                writer.writerow([
                    threat.get('indicator', ''),
                    threat.get('property', '')
                ])
        print(f"Saved CSV: {csv_file}")
        
        return sorted_threats

def categorize_indicators(ndjson_file: str):
    """Categorize indicators from NDJSON file based on property values"""
    
    # Initialize result dictionary with empty lists for each category
    categorized_data = {category: [] for category in categories.keys()}
    
    # Read the NDJSON file
    try:
        with open(ndjson_file, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    threat = json.loads(line.strip())
                    indicator = threat.get('indicator', '')
                    property_value = threat.get('property', '')
                    
                    if not indicator or not property_value:
                        continue
                    
                    # Find which category this property belongs to (case-insensitive)
                    property_lower = property_value.lower()
                    for category, properties in categories.items():
                        # Convert all properties to lowercase for comparison
                        properties_lower = [prop.lower() for prop in properties]
                        if property_lower in properties_lower:
                            # Only add if category hasn't reached 1000 items limit
                            if len(categorized_data[category]) < 1000:
                                categorized_data[category].append(indicator)
                            break
                    
                except json.JSONDecodeError:
                    continue
                    
    except FileNotFoundError:
        print(f"Error: {ndjson_file} file not found")
        return
    
    # Write categorized data to JSON file
    with open('ib-base-category.json', 'w', encoding='utf-8') as f:
        json.dump(categorized_data, f, indent=2, ensure_ascii=False)
    
    # Create individual text files for each category
    for category, indicators in categorized_data.items():
        if indicators:  # Only create file if category has indicators
            filename = f"{category}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                for indicator in indicators:
                    f.write(indicator + '\n')
            print(f"Created: {filename} ({len(indicators)} indicators)")
    
    # Print summary
    total_indicators = sum(len(indicators) for indicators in categorized_data.values())
    print(f"\nCategorization complete! Total indicators: {total_indicators}")
    print("Category breakdown:")
    for category, indicators in categorized_data.items():
        print(f"  {category}: {len(indicators)} indicators")
    print(f"JSON output saved to: ib-base-category.json")
    print(f"Text files created for each category")


def main():
    """Main processing function"""
    # Default S3 parameters
    default_bucket = "rpz-zones-useast"
    default_key = "cacheFiles/infoblox-base.json.gz"
    
    if len(sys.argv) == 1:
        # No arguments - use defaults
        bucket = default_bucket
        key = default_key
        local_filename = os.path.basename(key)
        input_file = download_from_s3(bucket, key, local_filename)
    elif len(sys.argv) == 2:
        # One argument - specific filename
        input_file = sys.argv[1]
    elif len(sys.argv) == 3:
        # Two arguments - bucket and key
        bucket = sys.argv[1]
        key = sys.argv[2]
        local_filename = os.path.basename(key)
        input_file = download_from_s3(bucket, key, local_filename)
    else:
        print("Usage:")
        print("  python3 index.py                                    # Use default S3 location")
        print("  python3 index.py <bucket> <key>                     # Download from S3")
        print("  python3 index.py <filename>                         # Use specific filename")
        return
    
    if not input_file:
        return
    
    filter = ThreatFilter()
    threats = filter.process_file(input_file)
    
    if threats:
        base_name = input_file.replace('.json.gz', '').replace('.json', '')
        sorted_threats = filter.sort_and_save(threats, base_name)
        
        print(f"\nSample (latest imported): {sorted_threats[0].get('imported', 'N/A')}")
        print(f"Sample (oldest imported): {sorted_threats[-1].get('imported', 'N/A')}")
        
        # Categorize the indicators
        ndjson_file = f"sorted_{base_name}.ndjson"
        print(f"\nStarting categorization...")
        categorize_indicators(ndjson_file)
    
    print("\nProcessing complete!")


if __name__ == "__main__":
    main()

