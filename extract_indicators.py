#!/usr/bin/env python3
"""
Extract only indicators from processed threat data
Creates indicators-only NDJSON and CSV files
"""

import json
import csv
import sys
from typing import Set

def extract_indicators_from_ndjson(input_file: str) -> Set[str]:
    """Extract unique indicators from NDJSON file"""
    indicators = set()
    
    print(f"Reading indicators from: {input_file}")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    try:
                        threat = json.loads(line)
                        indicator = threat.get('indicator', '').strip()
                        if indicator:
                            indicators.add(indicator)
                    except json.JSONDecodeError as e:
                        print(f"Warning: Skipping malformed JSON on line {line_num}: {e}")
                        continue
    
    except FileNotFoundError:
        print(f"Error: File {input_file} not found")
        return set()
    except Exception as e:
        print(f"Error reading file: {e}")
        return set()
    
    print(f"Found {len(indicators)} unique indicators")
    return indicators

def save_indicators(indicators: Set[str], base_name: str):
    """Save indicators as NDJSON and CSV"""
    # Sort indicators alphabetically for consistent output
    sorted_indicators = sorted(indicators)
    
    # Save as NDJSON (one indicator per line)
    ndjson_file = f"{base_name}_indicators.ndjson"
    with open(ndjson_file, 'w', encoding='utf-8') as f:
        for indicator in sorted_indicators:
            f.write(json.dumps({"indicator": indicator}) + '\n')
    print(f"Saved indicators NDJSON: {ndjson_file}")
    
    # Save as CSV
    csv_file = f"{base_name}_indicators.csv"
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['indicator'])  # Header
        for indicator in sorted_indicators:
            writer.writerow([indicator])
    print(f"Saved indicators CSV: {csv_file}")
    
    return len(sorted_indicators)

def main():
    """Main function"""
    if len(sys.argv) != 2:
        print("Usage: python3 extract_indicators.py <input_ndjson_file>")
        print("Example: python3 extract_indicators.py sorted_infoblox-base.ndjson")
        return
    
    input_file = sys.argv[1]
    base_name = input_file.replace('.ndjson', '').replace('.json', '')
    
    # Extract indicators
    indicators = extract_indicators_from_ndjson(input_file)
    
    if indicators:
        count = save_indicators(indicators, base_name)
        print(f"\nProcessing complete! Extracted {count} unique indicators.")
        
        # Show sample indicators
        sample_indicators = sorted(indicators)[:5]
        print(f"\nSample indicators:")
        for i, indicator in enumerate(sample_indicators, 1):
            print(f"  {i}. {indicator}")
        
        if len(indicators) > 5:
            print(f"  ... and {len(indicators) - 5} more")
    else:
        print("No indicators found or error occurred.")

if __name__ == "__main__":
    main()
