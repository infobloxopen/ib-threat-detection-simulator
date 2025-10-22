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
from datetime import datetime, timezone
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

# Maximum number of domains to sample per category (standard for consistency)
# This ensures all categories try to sample the same number of domains
# for fair comparison and consistent detection rate calculations
MAX_SAMPLE = 50

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
    
    def sample_domains(self, category: str, count: int, random_seed: Optional[int] = None) -> CategorySample:
        """
        Sample domains for a specific category, respecting TTL cache
        
        Args:
            category: Threat category name
            count: Number of domains to sample
            random_seed: Optional seed for reproducible sampling
            
        Returns:
            CategorySample with sampled domains and metadata
        """
        if category not in SUPPORTED_CATEGORIES:
            raise ValueError(f"Unsupported category: {category}. Supported: {SUPPORTED_CATEGORIES}")
        
        if category not in self.indicators:
            logger.warning(f"⚠️ No indicators found for category: {category}")
            return CategorySample(category, [], 0, datetime.now(timezone.utc).isoformat())
        
        # Set random seed if provided for reproducible results
        if random_seed is not None:
            random.seed(random_seed)
        
        # Special handling for DNST_Tunneling - bypass cache since it uses only one domain
        if category == "DNST_Tunneling":
            logger.info(f"🔄 DNST_Tunneling: Bypassing cache (uses single domain repeatedly)")
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
                          count_per_category: int = MAX_SAMPLE,
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

if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create sampler
    sampler = ThreatDomainSampler()
    
    # Sample MAX_SAMPLE domains per category (standard: 50)
    results = sampler.sample_all_categories(MAX_SAMPLE)
    
    # Print summary
    summary = sampler.get_sampling_summary()
    print(f"\n📊 Sampling Summary:")
    print(f"Total domains sampled: {summary['total_domains_sampled']}")
    print(f"Categories with samples: {summary['categories_sampled']}/{summary['total_categories']}")
    
    # Export results
    sampler.export_samples_to_json("sampled_domains.json")
