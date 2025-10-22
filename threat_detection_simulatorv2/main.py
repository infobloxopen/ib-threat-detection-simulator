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
        default=5,
        help='Number of domains to sample per category (default: 5)'
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
    """Save analysis results to files"""
    # Create output directory
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Save complete results as JSON
    json_file = output_dir / f"threat_analysis_v2_{mode}_{timestamp}.json"
    
    # Convert results to serializable format
    serializable_results = {}
    for category, result in results.items():
        if hasattr(result, 'to_dict'):
            serializable_results[category] = result.to_dict()
        else:
            serializable_results[category] = result
    
    with open(json_file, 'w') as f:
        json.dump(serializable_results, f, indent=2, default=str)
    
    logging.info(f"📁 Complete results saved to: {json_file}")
    
    # Generate summary report
    summary_file = output_dir / f"threat_summary_v2_{mode}_{timestamp}.txt"
    
    with open(summary_file, 'w') as f:
        f.write("Threat Detection Simulator v2 - Analysis Summary\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Execution Mode: {mode.upper()}\n")
        f.write(f"Output Format: {output_format}\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n\n")
        
        total_categories = len(results)
        total_domains = sum(len(result.domains) if hasattr(result, 'domains') else 0 for result in results.values())
        total_successful = sum(len(result.successful_domains) if hasattr(result, 'successful_domains') else 0 for result in results.values())
        total_detected = sum(len(result.detected_domains) if hasattr(result, 'detected_domains') else 0 for result in results.values())
        
        f.write("📊 Overall Statistics:\n")
        f.write(f"   Categories Analyzed: {total_categories}\n")
        f.write(f"   Total Domains: {total_domains}\n")
        f.write(f"   Successfully Resolved: {total_successful}\n")
        f.write(f"   Threats Detected: {total_detected}\n")
        
        if total_successful > 0:
            detection_rate = (total_detected / total_successful) * 100
            f.write(f"   Detection Rate: {detection_rate:.1f}%\n")
        
        f.write("\n📋 Per-Category Results:\n")
        f.write("-" * 40 + "\n")
        
        for category, result in results.items():
            f.write(f"\n{category}:\n")
            if hasattr(result, 'threat_summary'):
                summary = result.threat_summary
                f.write(f"   Domains: {len(result.domains) if hasattr(result, 'domains') else 0}\n")
                f.write(f"   Successful: {summary.get('total_successful_domains', 0)}\n")
                f.write(f"   Detected: {summary.get('detected_domains_count', 0)}\n")
                f.write(f"   Detection Rate: {summary.get('detection_rate', 0):.1f}%\n")
    
    logging.info(f"📄 Summary report saved to: {summary_file}")


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