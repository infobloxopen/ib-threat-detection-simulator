#!/usr/bin/env python3
# This script processes large compressed JSON threat intelligence files to extract recent, actionable threats.

# What it does:

# Loads a gzipped JSON file containing cybersecurity threat data
# Filters twice:
# Keeps only threats detected between 48-24 hours ago (yesterday's data)
# Then keeps only those that don't expire for 30+ days
# Sorts results by import date (newest first)
# Exports two files:
# sorted_[filename].ndjson - Full threat records, one per line
# sorted_[filename].csv - Summary with 5 key columns: indicator, detected, expiration, imported, property
# Purpose: Extract fresh threat intelligence that's both recently discovered and has long-term validity, making it ideal for security operations that need current, actionable data.

# Usage:
# The script can download from S3 using bucket/key or use a local file
# Default: bucket="rpz-zones-useast", key="cacheFiles/infoblox-base.json.gz"
# Command to run with defaults to S3 location (rpz-zones-useast/cacheFiles/infoblox-base.json.gz): python3 index.py
# Command to run with S3 params (provide bucket name and object key):   python3 index.py rpz-zones-useast cacheFiles/infoblox-base.json.gz
# Command to run with local file:  python3 index.py local infoblox-base.json.gz

import json
import gzip
import csv
import sys
import boto3
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any

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
    
    def __init__(self, expiration_days=30, detected_hours_start=48, detected_hours_end=24):
        self.expiration_cutoff = datetime.now() + timedelta(days=expiration_days)
        self.detected_start = datetime.now() - timedelta(hours=detected_hours_start)  # 48h ago
        self.detected_end = datetime.now() - timedelta(hours=detected_hours_end)      # 24h ago
        print(f"Filtering: expiration > {self.expiration_cutoff.date()}, detected between {detected_hours_start}h-{detected_hours_end}h ago")
    
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
        """Process JSON.gz file with two-stage filtering"""
        print(f"Processing: {file_path}")
        
        with gzip.open(file_path, 'rt', encoding='utf-8') as f:
            data = json.load(f)
            threats = data.get('Threats', [])
            
        print(f"Total threats: {len(threats)}")
        
        # Stage 1: Filter by detected date (between 48h-24h ago)
        detected_filtered = [
            t for t in threats 
            if self.detected_start <= self.parse_date(t.get('detected')) <= self.detected_end
        ]
        print(f"After detected filter: {len(detected_filtered)}")
        
        # Stage 2: Filter by expiration date
        final_filtered = [
            t for t in detected_filtered 
            if self.parse_date(t.get('expiration')) > self.expiration_cutoff
        ]
        print(f"Final result: {len(final_filtered)}")
        
        return final_filtered
    
    def sort_and_save(self, threats: List[Dict[str, Any]], base_name: str):
        """Sort by imported date and save top 500 as NDJSON and CSV"""
        # Sort by imported date (latest first)
        sorted_threats = sorted(
            threats,
            key=lambda t: self.parse_date(t.get('imported')),
            reverse=True
        )
        
        # Take only top 500
        top_threats = sorted_threats[:500]
        print(f"Selected top {len(top_threats)} records from {len(sorted_threats)} total")
        
        # Save NDJSON
        ndjson_file = f"sorted_{base_name}.ndjson"
        with open(ndjson_file, 'w', encoding='utf-8') as f:
            for threat in top_threats:
                f.write(json.dumps(threat) + '\n')
        print(f"Saved NDJSON: {ndjson_file}")
        
        # Save CSV
        csv_file = f"sorted_{base_name}.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['indicator', 'detected', 'expiration', 'imported', 'property'])
            for threat in top_threats:
                writer.writerow([
                    threat.get('indicator', ''),
                    threat.get('detected', ''),
                    threat.get('expiration', ''),
                    threat.get('imported', ''),
                    threat.get('property', '')
                ])
        print(f"Saved CSV: {csv_file}")
        
        return top_threats


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
        # One argument - could be local file
        if sys.argv[1] == "local":
            input_file = input("Enter local filename: ").strip()
        else:
            # Assume it's a local file
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
        print("  python3 index.py <local_filename>                   # Use local file")
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
    
    print("Processing complete!")


if __name__ == "__main__":
    main()

