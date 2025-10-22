#!/usr/bin/env python3
"""
Threat Detection Simulator v2 - Main Entry Point

This is the main entry point for the threat detection simulator v2, which orchestrates
the complete threat analysis pipeline: sampling, digging, and threat event fetching.

Key features:
- Automatic VM metadata detection from GCP
- Dynamic domain generation (DGA and DNST) 
- Real DNS execution (no simulations)
- Comprehensive threat event analysis
- Support for multiple output formats
- Extensible architecture for new threat categories

Usage:
    python3 main.py --log-level debug --mode advanced --output-format advanced
    python3 main.py --log-level info --mode basic --ttl 600

The script automatically detects GCP VM metadata and uses it for threat log analysis.
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Add current directory to path
sys.path.append('.')

from utils.sampler import ThreatDomainSampler
from utils.digger import dig_domains_for_categories
from utils.threat_fetcher import fetch_threats_for_categories
from utils.gcp_utils import get_vm_metadata_with_gcloud_fallback
from utils.dependency_checker import run_preflight_checks


def setup_logging(log_level: str) -> None:
    """Setup logging configuration based on log level"""
    level = logging.DEBUG if log_level == 'debug' else logging.INFO
    
    # Create logs directory if it doesn't exist
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Setup logging with both console and file output
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(logs_dir / f"simulator_v2_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        ]
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Threat Detection Simulator v2 - Advanced Threat Analysis Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --log-level debug --mode basic
  %(prog)s --log-level info --mode advanced --ttl 1800
  %(prog)s --log-level debug --mode advanced --output-format advanced

Modes:
  basic    - Process static categories + dynamic DGA domains
  advanced - Process static categories + dynamic DGA + DNST domains

Output Formats:
  basic    - Threat info only
  advanced - Threat info + DNS query details
        """
    )
    
    parser.add_argument(
        '--log-level',
        choices=['debug', 'info'],
        default='info',
        help='Logging level (default: info)'
    )
    
    parser.add_argument(
        '--mode',
        choices=['basic', 'advanced'],
        default='basic',
        help='Execution mode (default: basic)'
    )
    
    parser.add_argument(
        '--output-format', 
        choices=['basic', 'advanced'],
        default='basic',
        help='Output format detail level (default: basic)'
    )
    
    parser.add_argument(
        '--ttl',
        type=int,
        default=600,
        help='Domain cache TTL in seconds (default: 600)'
    )
    
    parser.add_argument(
        '--sample-count',
        type=int,
        default=50,
        help='Number of domains to sample per category (default: 50)'
    )
    
    parser.add_argument(
        '--skip-preflight',
        action='store_true',
        help='Skip preflight dependency checks'
    )
    
    parser.add_argument(
        '--simulation-mode',
        action='store_true',
        help='Use simulation mode for threat event fetching (for testing)'
    )
    
    return parser.parse_args()


def save_results(results: Dict, output_format: str, mode: str) -> None:
    """Save analysis results to files in v1-compatible format"""
    import csv
    
    # Create output directory (same as v1)
    output_dir = Path("category_output")
    output_dir.mkdir(exist_ok=True)
    
    # Define CSV headers based on output format (same as v1)
    if output_format == 'advanced':
        csv_headers = [
            "Domain Category",
            "Client DNS Query Domain", 
            "DNS Query in DNS logs",
            "Distinct domains in DNS logs",
            "Total Threat Count",
            "Distinct domain Threat Count", 
            "Detection Rate (%)"
        ]
    else:
        csv_headers = [
            "Domain Category",
            "Client DNS Query Domain",
            "Total Threat Count", 
            "Distinct domain Threat Count",
            "Detection Rate (%)"
        ]
    
    # Build CSV data and calculate totals
    csv_data = []
    total_client_queries = 0
    total_dns_queries = 0
    total_dns_domains = 0
    total_threat_counts = 0
    total_threat_domains = 0
    
    # Process each category
    for category_name, category_data in results.items():
        if hasattr(category_data, 'domains'):
            # Get REAL data from actual results - NO HARDCODING
            client_count = len(category_data.domains)
            total_client_queries += client_count
            
            # Get actual DNS query results
            dns_count = len(getattr(category_data, 'successful_domains', category_data.domains))
            dns_domains = len(set(getattr(category_data, 'successful_domains', category_data.domains)))
            
            # Get actual threat detection results
            detected_domains = getattr(category_data, 'detected_domains', [])
            threat_count = len(detected_domains)
            threat_domains = len(set(detected_domains))
            
            # Calculate REAL detection rate
            detection_rate = (threat_domains / client_count * 100) if client_count > 0 else 0.0
            
            total_dns_queries += dns_count
            total_dns_domains += dns_domains
            total_threat_counts += threat_count
            total_threat_domains += threat_domains
            
            # Build CSV row with REAL data
            row = {
                "Domain Category": category_name,
                "Client DNS Query Domain": client_count,
                "Total Threat Count": threat_count,
                "Distinct domain Threat Count": threat_domains,
                "Detection Rate (%)": f"{detection_rate:.2f}"
            }
            
            if output_format == 'advanced':
                row["DNS Query in DNS logs"] = dns_count
                row["Distinct domains in DNS logs"] = dns_domains
            
            csv_data.append(row)
    
    # Calculate overall detection rate
    overall_detection_rate = (total_threat_domains / total_client_queries * 100) if total_client_queries > 0 else 0.0
    
    # Add TOTAL row
    total_row = {
        "Domain Category": "TOTAL",
        "Client DNS Query Domain": total_client_queries,
        "Total Threat Count": total_threat_counts,
        "Distinct domain Threat Count": total_threat_domains,
        "Detection Rate (%)": f"{overall_detection_rate:.2f}"
    }
    
    if output_format == 'advanced':
        total_row["DNS Query in DNS logs"] = total_dns_queries
        total_row["Distinct domains in DNS logs"] = total_dns_domains
    
    csv_data.append(total_row)
    
    # Write CSV file (same filename as v1)
    csv_file = output_dir / "threat_detection_results.csv"
    with open(csv_file, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
        writer.writeheader()
        
        # Add simulation note (same as v1)
        note_row = {}
        for header in csv_headers:
            if header == 'Domain Category':
                note_row[header] = "NOTE: SIMULATION"
            elif header == 'Client DNS Query Domain':
                note_row[header] = "For simulating DNST we are using 1 TLD as input for exfiltration and we get multiple events with same TLD"
            else:
                note_row[header] = ""
        writer.writerow(note_row)
        
        # Add empty row for separation
        empty_row = {header: "" for header in csv_headers}
        writer.writerow(empty_row)
        
        # Write actual data
        writer.writerows(csv_data)
    
    # Save domain cache (same as v1)
    used_domains = {}
    for category_name, category_data in results.items():
        if hasattr(category_data, 'domains'):
            used_domains[category_name] = category_data.domains
    
    save_domain_cache(str(output_dir), used_domains)
    
    # Save individual category files (same as v1)
    save_individual_category_files(output_dir, results)
    
    # Print summary in v1 format
    logging.info("="*80)
    logging.info("📊 THREAT DETECTION SIMULATION SUMMARY")
    logging.info("="*80)
    logging.info("⚠️  NOTE: SIMULATION - For simulating DNST we are using 1 TLD as input for exfiltration and we get multiple events with same TLD")
    logging.info("="*80)
    logging.info(f"📁 CSV file generated: {csv_file}")
    logging.info(f"🎯 Output Format: {output_format.upper()}")
    logging.info("")
    logging.info("📈 Category Breakdown:")
    
    # Print category breakdown using REAL data from results
    for category_name, category_data in results.items():
        if hasattr(category_data, 'domains'):
            # Use ACTUAL data from the analysis - NO HARDCODING
            client_count = len(category_data.domains)
            
            # Get real DNS query results
            dns_count = len(getattr(category_data, 'successful_domains', category_data.domains))
            dns_domains = len(set(getattr(category_data, 'successful_domains', category_data.domains)))
            
            # Get real threat detection results
            detected_domains = getattr(category_data, 'detected_domains', [])
            threat_count = len(detected_domains)
            threat_domains = len(set(detected_domains))
            
            # Calculate REAL detection rate
            detection_rate = (threat_domains / client_count * 100) if client_count > 0 else 0.0
            
            logging.info(f"{category_name:<20} | Client: {client_count:3} | DNS: {dns_count:3} | DNS Domains: {dns_domains:3} | Threats: {threat_count:3} | Threat Domains: {threat_domains:3} | Detection: {detection_rate:6.2f}%")


def save_individual_category_files(output_dir: Path, results: Dict) -> None:
    """Save individual JSON files for each category (same as v1)"""
    for category_name, category_data in results.items():
        if not hasattr(category_data, 'domains'):
            continue
            
        # Clean category name for filename (replace & with _and_)
        clean_category = category_name.replace('&', '_and_').replace(' ', '_')
        
        try:
            # 1. Save DNS logs file
            dns_logs_file = output_dir / f"dns_logs_{clean_category}.json"
            dns_logs_data = getattr(category_data, 'dns_logs', [])
            with open(dns_logs_file, 'w') as f:
                json.dump(dns_logs_data, f, indent=2, default=str)
            
            # 2. Save threat events file  
            threat_events_file = output_dir / f"threat_event_{clean_category}.json"
            threat_events_data = getattr(category_data, 'threat_events', [])
            with open(threat_events_file, 'w') as f:
                json.dump(threat_events_data, f, indent=2, default=str)
            
            # 3. Save non-detected domains file
            non_detected_file = output_dir / f"non_detected_domains_{clean_category}.json"
            
            # Calculate non-detected domains
            all_domains = set(category_data.domains)
            detected_domains = set(getattr(category_data, 'detected_domains', []))
            non_detected = list(all_domains - detected_domains)
            
            with open(non_detected_file, 'w') as f:
                json.dump(non_detected, f, indent=2)
                
            logging.debug(f"📁 Saved individual files for {category_name}")
            
        except Exception as e:
            logging.error(f"❌ Error saving individual files for {category_name}: {e}")


def save_domain_cache(output_dir: str, used_domains: Dict[str, List[str]]) -> None:
    """Save used domains to cache file with current timestamp (v1 compatible)"""
    cache_path = Path(output_dir) / "domain_cache.json"
    current_timestamp = datetime.now().isoformat()
    
    # Create cache data structure (same as v1)
    cache_data = {}
    for category, domains in used_domains.items():
        cache_data[category] = {
            'domains': domains,
            'timestamp': current_timestamp
        }
    
    try:
        with open(cache_path, 'w') as f:
            json.dump(cache_data, f, indent=2)
        
        total_domains = sum(len(domains) for domains in used_domains.values())
        logging.info(f"💾 Saved domain cache: {total_domains} domains across {len(used_domains)} categories")
        logging.info(f"� Cache file: {cache_path}")
        
    except Exception as e:
        logging.error(f"❌ Error saving domain cache: {e}")


def run_preflight_and_setup(args) -> Dict[str, str]:
    """Run preflight checks and setup VM metadata"""
    logger = logging.getLogger(__name__)
    
    # Run preflight checks
    if not args.skip_preflight:
        logger.info("🔍 Running preflight dependency checks...")
        preflight_result = run_preflight_checks(skip_preflight=False)
        
        if not preflight_result.passed:
            logger.error(f"❌ Preflight checks failed with {len(preflight_result.errors)} error(s)")
            for error in preflight_result.errors:
                logger.error(f"   - {error}")
            logger.error("Fix issues or use --skip-preflight to override")
            sys.exit(1)
        
        logger.info("✅ Preflight checks passed")
    else:
        logger.warning("⚠️ Skipping preflight checks")
    
    # Detect VM metadata
    logger.info("🔍 Detecting GCP VM metadata...")
    vm_metadata = get_vm_metadata_with_gcloud_fallback()
    
    if not vm_metadata:
        logger.error("❌ Could not detect VM metadata")
        logger.error("   This script should run on a GCP VM with metadata access")
        logger.error("   Or ensure gcloud CLI is properly configured")
        sys.exit(1)
    
    logger.info("✅ VM metadata detected successfully")
    logger.info(f"   Project: {vm_metadata.get('project_id', 'Unknown')}")
    logger.info(f"   Instance: {vm_metadata.get('instance_id', 'Unknown')}")
    logger.info(f"   Zone: {vm_metadata.get('zone', 'Unknown')}")
    
    return vm_metadata


def sample_domains_for_mode(sampler, args, mode: str) -> Dict:
    """Sample domains based on execution mode"""
    logger = logging.getLogger(__name__)
    
    if mode == 'basic':
        logger.info("🤖 BASIC MODE: Sampling static categories + DGA domains")
        categories_to_sample = [
            'Phishing', 'Lookalikes', 'TDS', 'Command_&_Control',
            'Emerging_Domains', 'High_Risk', 'Malicious_Domains', 'DGA_Malware'
        ]
    else:  # advanced
        logger.info("🚀 ADVANCED MODE: Sampling static categories + DGA + DNST domains")
        categories_to_sample = [
            'Phishing', 'Lookalikes', 'TDS', 'Command_&_Control',
            'Emerging_Domains', 'High_Risk', 'Malicious_Domains', 
            'DGA_Malware', 'DNST_Tunneling'
        ]
    
    # Sample domains for selected categories
    logger.info(f"📦 Sampling {args.sample_count} domains per category...")
    sampled_domains = {}
    
    for category in categories_to_sample:
        try:
            result = sampler.sample_domains(category, args.sample_count)
            sampled_domains[category] = result
            logger.info(f"   ✅ {category}: {len(result.domains)} domains sampled")
        except Exception as e:
            logger.error(f"   ❌ {category}: Failed to sample - {e}")
            continue
    
    logger.info(f"✅ Sampling completed: {len(sampled_domains)} categories")
    return sampled_domains


def main():
    """Main execution function"""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Setup logging
        setup_logging(args.log_level)
        logger = logging.getLogger(__name__)
        
        logger.info("🚀 Starting Threat Detection Simulator v2")
        logger.info("=" * 80)
        logger.info(f"🎯 Execution Mode: {args.mode.upper()}")
        logger.info(f"📊 Output Format: {args.output_format}")
        logger.info(f"🔍 Log Level: {args.log_level}")
        logger.info(f"⏰ Cache TTL: {args.ttl} seconds")
        logger.info(f"📦 Sample Count: {args.sample_count} per category")
        logger.info("=" * 80)
        
        # Run preflight and get VM metadata
        vm_metadata = run_preflight_and_setup(args)
        
        # Initialize sampler
        logger.info("🎲 Initializing domain sampler...")
        sampler = ThreatDomainSampler()
        
        # Sample domains based on mode
        sampled_domains = sample_domains_for_mode(sampler, args, args.mode)
        
        # Dig domains
        logger.info("🔍 Starting DNS resolution for sampled domains...")
        dig_results = dig_domains_for_categories(sampled_domains)
        
        # Log dig summary
        total_successful = sum(len(result.successful_domains) for result in dig_results.values())
        total_domains = sum(len(result.domains) for result in dig_results.values())
        logger.info(f"✅ DNS resolution completed: {total_successful}/{total_domains} domains resolved")
        
        # Fetch threat events
        logger.info("🎯 Fetching threat detection events...")
        
        # Determine mode for threat fetching
        threat_mode = "simulation" if args.simulation_mode else "gcp"
        
        threat_results = fetch_threats_for_categories(
            dig_results,
            mode=threat_mode,
            project_id=vm_metadata.get('project_id'),
            vm_instance_id=vm_metadata.get('instance_id'),
            vm_zone=vm_metadata.get('zone'),
            hours_back=2.0
        )
        
        # Log threat summary
        total_detected = sum(len(result.detected_domains) for result in threat_results.values())
        overall_detection_rate = (total_detected / total_successful * 100) if total_successful > 0 else 0
        
        logger.info(f"✅ Threat analysis completed: {total_detected}/{total_successful} threats detected ({overall_detection_rate:.1f}%)")
        
        # Save results
        logger.info("💾 Saving analysis results...")
        save_results(threat_results, args.output_format, args.mode)
        
        # Final summary
        logger.info("=" * 80)
        logger.info("🎉 Threat Detection Simulator v2 completed successfully!")
        logger.info("📊 Final Statistics:")
        logger.info(f"   Categories: {len(threat_results)}")
        logger.info(f"   Total Domains: {total_domains}")
        logger.info(f"   DNS Success: {total_successful}/{total_domains} ({(total_successful/total_domains*100) if total_domains > 0 else 0:.1f}%)")
        logger.info(f"   Threats Detected: {total_detected}/{total_successful} ({overall_detection_rate:.1f}%)")
        logger.info("=" * 80)
        
    except KeyboardInterrupt:
        logger.warning("⚠️ Execution interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"💥 Unexpected error: {e}")
        logger.debug("Stack trace:", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()