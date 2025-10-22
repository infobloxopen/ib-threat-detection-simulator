#!/usr/bin/env python3
"""
Quick integration test for v2 threat detection simulator
Tests: sampler → digger → threat_fetcher pipeline
"""

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

from threat_detection_simulatorv2.utils.sampler import ThreatDomainSampler
from threat_detection_simulatorv2.utils.digger import dig_domains_for_categories
from threat_detection_simulatorv2.utils.threat_fetcher import fetch_threats_for_categories

def main():
    print('🚀 Testing v2 threat detection simulator: sampler → digger → threat_fetcher')

    # Sample domains
    indicators_file = "/Users/gshterenstein/Documents/InfobloxOpen/ib-threat-detection-simulator/threat_detection_simulatorv2/ib-base-category.json"
    sampler = ThreatDomainSampler(indicators_file=indicators_file)
    samples = sampler.sample_all_categories(5)  # 5 domains per category
    print(f'\n📊 Sampled {len(samples)} categories')

    # Dig domains
    dig_results = dig_domains_for_categories(samples)
    print(f'\n🔍 Dig completed for {len(dig_results)} categories')

    # Fetch threat events
    threat_results = fetch_threats_for_categories(dig_results, mode='simulation')
    print(f'\n🎯 Threat detection completed for {len(threat_results)} categories')

    # Display summary
    print('\n📈 Detection Summary:')
    total_successful = 0
    total_detected = 0

    for category, result in threat_results.items():
        summary = result.threat_summary
        successful = summary['total_successful_domains']
        detected = summary['detected_domains_count']
        rate = summary['detection_rate']
        total_successful += successful
        total_detected += detected
        
        print(f'  {category}: {detected}/{successful} detected ({rate:.1f}%)')

    overall_rate = (total_detected / total_successful * 100) if total_successful > 0 else 0.0
    print(f'\n🎯 Overall: {total_detected}/{total_successful} detected ({overall_rate:.1f}%)')
    print('✅ v2 threat detection simulator integration test completed successfully!')

if __name__ == "__main__":
    main()