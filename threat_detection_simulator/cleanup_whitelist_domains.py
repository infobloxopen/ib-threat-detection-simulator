#!/usr/bin/env python3
"""
One-time cleanup script to remove domains from ib-base-category.json 
that have SLDs matching those in the global whitelist file.

This addresses the issue of low detection rates caused by whitelisted domains
being included in threat categories.
"""

import json
import re
from urllib.parse import urlparse
from collections import defaultdict
import os
import sys
from typing import Set, Dict, List

def extract_sld(domain: str) -> str:
    """
    Extract the second-level domain (SLD) from a domain.
    
    Examples:
    - "sub.example.com" -> "example.com"
    - "example.com" -> "example.com"  
    - "test.github.io" -> "github.io"
    """
    try:
        # Remove protocol if present
        if '://' in domain:
            domain = urlparse(domain).netloc or domain
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Split domain parts
        parts = domain.lower().strip().split('.')
        
        # Handle edge cases
        if len(parts) < 2:
            return domain.lower()
        
        # For most cases, return last two parts (SLD)
        # Special handling for common second-level TLDs could be added here
        # For now, keeping it simple
        return '.'.join(parts[-2:])
        
    except Exception as e:
        print(f"Warning: Could not extract SLD from '{domain}': {e}")
        return domain.lower()

def load_whitelist_slds(whitelist_file: str) -> Set[str]:
    """
    Load all SLDs from the global whitelist file.
    
    Args:
        whitelist_file (str): Path to the global whitelist TSV file
        
    Returns:
        Set[str]: Set of whitelisted SLDs
    """
    whitelist_slds = set()
    
    try:
        print(f"📥 Loading whitelist file: {whitelist_file}")
        
        with open(whitelist_file, 'r', encoding='utf-8') as f:
            line_count = 0
            for line in f:
                line = line.strip()
                if not line:
                    continue
                    
                line_count += 1
                
                # Parse TSV format: domain \t type \t category \t metadata
                parts = line.split('\t')
                if len(parts) >= 1:
                    domain = parts[0].strip()
                    if domain:
                        sld = extract_sld(domain)
                        whitelist_slds.add(sld)
                
                # Progress indicator for large files
                if line_count % 50000 == 0:
                    print(f"   Processed {line_count:,} whitelist entries...")
        
        print(f"✅ Loaded {len(whitelist_slds):,} unique SLDs from {line_count:,} whitelist entries")
        
    except FileNotFoundError:
        print(f"❌ Error: Whitelist file not found: {whitelist_file}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error loading whitelist: {e}")
        sys.exit(1)
    
    return whitelist_slds

def clean_threat_categories(categories_file: str, whitelist_slds: Set[str]) -> Dict:
    """
    Remove domains from threat categories that have SLDs matching the whitelist.
    
    Args:
        categories_file (str): Path to the ib-base-category.json file
        whitelist_slds (Set[str]): Set of whitelisted SLDs
        
    Returns:
        Dict: Cleaned categories data
    """
    try:
        print(f"📥 Loading threat categories: {categories_file}")
        
        with open(categories_file, 'r', encoding='utf-8') as f:
            categories = json.load(f)
        
        print(f"✅ Loaded {len(categories)} threat categories")
        
        # Track removal statistics
        removal_stats = defaultdict(lambda: {'original': 0, 'removed': 0, 'kept': 0})
        total_removed = 0
        total_original = 0
        
        # Process each category
        for category_name, domains in categories.items():
            original_count = len(domains)
            removal_stats[category_name]['original'] = original_count
            total_original += original_count
            
            # Filter out domains with whitelisted SLDs
            cleaned_domains = []
            removed_domains = []
            
            for domain in domains:
                sld = extract_sld(domain)
                if sld in whitelist_slds:
                    removed_domains.append(domain)
                    total_removed += 1
                else:
                    cleaned_domains.append(domain)
            
            # Update category with cleaned domains
            categories[category_name] = cleaned_domains
            removal_stats[category_name]['removed'] = len(removed_domains)
            removal_stats[category_name]['kept'] = len(cleaned_domains)
            
            # Log category-specific results
            if removed_domains:
                print(f"   {category_name:20}: {original_count:5} -> {len(cleaned_domains):5} "
                      f"(removed {len(removed_domains):3} domains)")
                
                # Show some examples of removed domains
                if len(removed_domains) <= 5:
                    print(f"      Removed: {', '.join(removed_domains)}")
                else:
                    print(f"      Removed examples: {', '.join(removed_domains[:3])} ... (+{len(removed_domains)-3} more)")
        
        # Print summary statistics
        print("\n" + "="*80)
        print("📊 CLEANUP SUMMARY")
        print("="*80)
        print(f"Total domains processed: {total_original:,}")
        print(f"Total domains removed:   {total_removed:,}")
        print(f"Total domains kept:      {total_original - total_removed:,}")
        print(f"Removal rate:            {(total_removed/total_original)*100:.2f}%")
        
        print(f"\n📋 Per-category breakdown:")
        for category_name, stats in removal_stats.items():
            if stats['removed'] > 0:
                removal_rate = (stats['removed'] / stats['original']) * 100
                print(f"   {category_name:20}: {stats['original']:4} -> {stats['kept']:4} "
                      f"({stats['removed']:3} removed, {removal_rate:5.1f}%)")
        
        return categories
        
    except FileNotFoundError:
        print(f"❌ Error: Categories file not found: {categories_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing JSON file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error cleaning categories: {e}")
        sys.exit(1)

def save_cleaned_categories(categories: Dict, output_file: str, backup_original: bool = True):
    """
    Save the cleaned categories to file and optionally backup the original.
    
    Args:
        categories (Dict): Cleaned categories data
        output_file (str): Path to save the cleaned categories
        backup_original (bool): Whether to backup the original file
    """
    try:
        # Backup original file if requested
        if backup_original and os.path.exists(output_file):
            backup_file = f"{output_file}.backup.{int(__import__('time').time())}"
            import shutil
            shutil.copy2(output_file, backup_file)
            print(f"💾 Original file backed up to: {backup_file}")
        
        # Save cleaned categories
        print(f"💾 Saving cleaned categories to: {output_file}")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(categories, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Cleaned categories saved successfully")
        
        # Verify the saved file
        with open(output_file, 'r', encoding='utf-8') as f:
            verification = json.load(f)
        
        total_domains = sum(len(domains) for domains in verification.values())
        print(f"🔍 Verification: Saved file contains {len(verification)} categories with {total_domains:,} total domains")
        
    except Exception as e:
        print(f"❌ Error saving cleaned categories: {e}")
        sys.exit(1)

def main():
    """Main function to execute the cleanup process."""
    
    print("🧹 Starting one-time cleanup of threat categories")
    print("="*60)
    print("Purpose: Remove domains with SLDs matching global whitelist")
    print("="*60)
    
    # File paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    whitelist_file = os.path.join(script_dir, "global_whitelist (3).tsv")
    categories_file = os.path.join(script_dir, "ib-base-category.json")
    
    # Verify files exist
    if not os.path.exists(whitelist_file):
        print(f"❌ Error: Whitelist file not found: {whitelist_file}")
        print("Please ensure 'global_whitelist (3).tsv' is in the same directory as this script")
        sys.exit(1)
    
    if not os.path.exists(categories_file):
        print(f"❌ Error: Categories file not found: {categories_file}")
        print("Please ensure 'ib-base-category.json' is in the same directory as this script")
        sys.exit(1)
    
    try:
        # Step 1: Load whitelist SLDs
        print("\n🔍 Step 1: Loading global whitelist SLDs")
        whitelist_slds = load_whitelist_slds(whitelist_file)
        
        # Step 2: Clean threat categories
        print("\n🧹 Step 2: Cleaning threat categories")
        cleaned_categories = clean_threat_categories(categories_file, whitelist_slds)
        
        # Step 3: Save cleaned categories
        print("\n💾 Step 3: Saving cleaned categories")
        save_cleaned_categories(cleaned_categories, categories_file, backup_original=True)
        
        print("\n" + "="*60)
        print("✅ CLEANUP COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("🎯 Impact: This should significantly improve detection rates")
        print("📈 The sales demo tool will now use the cleaned threat categories")
        print("🔄 This cleanup was a one-time operation and does not need to be repeated")
        
        print(f"\n📋 Next steps:")
        print(f"   1. Test the sales demo tool with improved detection rates")
        print(f"   2. Original file backed up with timestamp for safety")
        print(f"   3. The cleanup is complete and ready for production use")
        
    except KeyboardInterrupt:
        print("\n❌ Cleanup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error during cleanup: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
