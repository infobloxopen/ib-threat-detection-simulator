#!/usr/bin/env python3
"""
Threat Detection Simulator v2 - Main Entry Point

This is the main entry point for the threat detection simulator v2, which orchestrates
the complete threat analysis pipeline: sampling, digging, and threat event fetching.

Key features:
- Au        try:
            result = sampler.sample_domains(category, args.sample_count, simulation_mode=args.simulation_mode)
            sampled_domains[category] = result
            logger.info(f"   ✅ {category}: {result.count} domains sampled")
        except Exception as e:
            logger.error(f"   ❌ {category}: sampling failed - {e}")
            continue VM metadata detection from GCP
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
from utils.threat_fetcher import ThreatEventFetcher, FetcherConfig
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
    # NOTE: Advanced late-detection features (salvage pass & streaming/backfill) are enabled internally
    # with sensible defaults and intentionally not exposed as CLI flags to preserve README contract.
    
    return parser.parse_args()


def save_results(results: Dict, output_format: str, mode: str) -> None:
    """Save analysis results to files in v1-compatible format"""
    # This function is kept for backward compatibility
    # The actual saving is now done in save_v1_compatible_results
    pass


def save_individual_category_files(output_dir: Path, results: Dict) -> None:
    """(Deprecated) Individual category files saving retained for backward compatibility"""
    for category_name, category_data in results.items():
        if not hasattr(category_data, 'domains'):
            continue
        clean_category = category_name.replace('&', '_and_').replace(' ', '_')
        try:
            dns_logs_file = output_dir / f"dns_logs_{clean_category}.json"
            dns_logs_data = getattr(category_data, 'dns_logs', [])
            with open(dns_logs_file, 'w') as f:
                json.dump(dns_logs_data, f, indent=2, default=str)
            threat_events_file = output_dir / f"threat_event_{clean_category}.json"
            threat_events_data = getattr(category_data, 'threat_events', [])
            with open(threat_events_file, 'w') as f:
                json.dump(threat_events_data, f, indent=2, default=str)
            non_detected_file = output_dir / f"non_detected_domains_{clean_category}.json"
            all_domains = set(category_data.domains)
            detected_domains = set(getattr(category_data, 'detected_domains', []))
            non_detected = list(all_domains - detected_domains)
            with open(non_detected_file, 'w') as f:
                json.dump(non_detected, f, indent=2)
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
            result = sampler.sample_domains(category, args.sample_count, simulation_mode=args.simulation_mode)
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
        
        # Instantiate fetcher directly to capture health report & performance metrics
        fetcher_cfg = FetcherConfig(
            batch_size=25,
            parallel_batches=False,
            per_batch_timeout=60,
            retry_attempts=3,
            # Internal late-detection defaults (hidden):
            salvage_enabled=True,
            salvage_wait_seconds=5,
            streaming_mode=True,
            streaming_poll_interval=2.0,
            streaming_max_seconds=30,
            streaming_stability_rounds=2
        )
        fetcher = ThreatEventFetcher(
            mode=threat_mode,
            project_id=vm_metadata.get('project_id'),
            vm_instance_id=vm_metadata.get('instance_id'),
            vm_zone=vm_metadata.get('zone'),
            hours_back=2.0,
            fast_mode=False,  # fast mode disabled by default (hidden)
            config=fetcher_cfg
        )
        threat_results = fetcher.fetch_threats_for_categories(dig_results)
        
        # Log threat summary (raw vs unique)
        total_detected_raw = sum(len(result.detected_domains) for result in threat_results.values())
        raw_detection_rate = (total_detected_raw / total_successful * 100) if total_successful > 0 else 0

        unique_domain_total = 0
        unique_detected_total = 0
        for category, dig_result in dig_results.items():
            unique_domains = set(dig_result.domains)
            unique_domain_total += len(unique_domains)
            detected_unique = set(threat_results[category].detected_domains).intersection(unique_domains)
            unique_detected_total += len(detected_unique)

        unique_detection_rate = (unique_detected_total / unique_domain_total * 100) if unique_domain_total > 0 else 0

        logger.info(f"✅ Threat analysis completed (raw): {total_detected_raw}/{total_successful} detected ({raw_detection_rate:.1f}%)")
        logger.info(f"✅ Threat analysis completed (unique domains): {unique_detected_total}/{unique_domain_total} detected ({unique_detection_rate:.1f}%)")
        
        # Save results in v1-compatible format
        logger.info("💾 Saving analysis results in v1-compatible format...")
        from utils.results_saver import save_v1_compatible_results
        save_v1_compatible_results(threat_results, dig_results, args.output_format, args.mode, vm_metadata)

        # Persist performance metrics & health report
        perf_metrics = {}
        for cat, res in threat_results.items():
            if hasattr(res, 'threat_summary'):
                late_salvage = fetcher.health_report['late_detection']['categories_salvaged'].get(cat, {})
                late_stream = fetcher.health_report['late_detection']['categories_streamed'].get(cat, {})
                perf_metrics[cat] = {
                    'fetch_duration_seconds': res.threat_summary.get('fetch_duration_seconds'),
                    'detected_domains_count': res.threat_summary.get('detected_domains_count'),
                    'undetected_domains_count': res.threat_summary.get('undetected_domains_count'),
                    'detection_rate': res.threat_summary.get('detection_rate'),
                    'no_logs_found': res.threat_summary.get('no_logs_found'),
                    'query_failed': res.threat_summary.get('query_failed'),
                    'late_salvage_added_events': late_salvage.get('added_events', 0),
                    'late_salvage_domains': late_salvage.get('late_domains_detected', []),
                    'streaming_final_detected_count': late_stream.get('final_detected_count'),
                    'streaming_duration_seconds': late_stream.get('duration_seconds')
                }
        output_dir = Path('category_output')
        output_dir.mkdir(exist_ok=True)
        with open(output_dir / 'performance_metrics.json', 'w') as f:
            json.dump(perf_metrics, f, indent=2)
        with open(output_dir / 'health_report.json', 'w') as f:
            json.dump(fetcher.health_report, f, indent=2)
        logger.info("💾 Saved performance metrics: category_output/performance_metrics.json")
        logger.info("💾 Saved health report: category_output/health_report.json")
        
        # Final summary (provide both raw & unique domain perspectives)
        logger.info("=" * 80)
        logger.info("🎉 Threat Detection Simulator completed successfully!")
        logger.info("📊 Final Statistics:")
        logger.info(f"   Categories: {len(threat_results)}")
        logger.info(f"   Total Raw Queries: {total_domains}")
        logger.info(f"   Total Unique Domains (DNST dedup applied): {unique_domain_total}")
        logger.info(f"   DNS Success (raw): {total_successful}/{total_domains} ({(total_successful/total_domains*100) if total_domains > 0 else 0:.1f}%)")
        logger.info(f"   Threats Detected (raw): {total_detected_raw}/{total_successful} ({raw_detection_rate:.1f}%)")
        logger.info(f"   Threats Detected (unique domains): {unique_detected_total}/{unique_domain_total} ({unique_detection_rate:.1f}%)")
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