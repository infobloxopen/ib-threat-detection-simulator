"""
Unit tests for the Threat Detection Simulator - Domain Sampler Module

Tests cover:
1. Domain cache TTL functionality
2. Domain sampling logic and filtering
3. Category sample objects
4. Error handling and edge cases
5. JSON import/export functionality
6. Integration scenarios
"""

import json
import pytest
import tempfile
import shutil
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, mock_open

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from utils.sampler import (
    DomainCache, 
    ThreatDomainSampler, 
    DomainSample, 
    CategorySample,
    SUPPORTED_CATEGORIES,
    MAX_SAMPLE,
    sample_domains_for_category,
    create_category_objects
)


class TestDomainSample:
    """Test DomainSample dataclass"""
    
    def test_domain_sample_creation(self):
        """Test basic DomainSample creation"""
        timestamp = datetime.now(timezone.utc).isoformat()
        sample = DomainSample(
            domain="evil.com",
            category="Phishing", 
            sampled_at=timestamp
        )
        
        assert sample.domain == "evil.com"
        assert sample.category == "Phishing"
        assert sample.sampled_at == timestamp
        assert sample.last_used is None
    
    def test_domain_sample_to_dict(self):
        """Test DomainSample serialization"""
        timestamp = datetime.now(timezone.utc).isoformat()
        sample = DomainSample(
            domain="malware.com",
            category="Malicious_Domains",
            sampled_at=timestamp,
            last_used=timestamp
        )
        
        data = sample.to_dict()
        expected = {
            "domain": "malware.com",
            "category": "Malicious_Domains", 
            "sampled_at": timestamp,
            "last_used": timestamp
        }
        
        assert data == expected


class TestCategorySample:
    """Test CategorySample dataclass"""
    
    def test_category_sample_creation(self):
        """Test basic CategorySample creation"""
        timestamp = datetime.now(timezone.utc).isoformat()
        domains = ["evil1.com", "evil2.com", "evil3.com"]
        
        sample = CategorySample(
            category="TDS",
            domains=domains,
            sampled_count=3,
            sampled_at=timestamp
        )
        
        assert sample.category == "TDS"
        assert sample.domains == domains
        assert sample.sampled_count == 3
        assert sample.sampled_at == timestamp
    
    def test_category_sample_to_dict(self):
        """Test CategorySample serialization"""
        timestamp = datetime.now(timezone.utc).isoformat()
        sample = CategorySample(
            category="Command_&_Control",
            domains=["c2-1.com", "c2-2.com"],
            sampled_count=2,
            sampled_at=timestamp
        )
        
        data = sample.to_dict()
        expected = {
            "category": "Command_&_Control",
            "domains": ["c2-1.com", "c2-2.com"],
            "sampled_count": 2,
            "sampled_at": timestamp
        }
        
        assert data == expected


class TestDomainCache:
    """Test DomainCache functionality"""
    
    def setup_method(self):
        """Setup test environment with temporary files"""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_file = Path(self.temp_dir) / "test_cache.json"
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_cache_initialization_new_file(self):
        """Test cache initialization with new file"""
        cache = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        assert cache.ttl_seconds == 300
        assert self.cache_file.exists()
        assert len(cache.cache) == len(SUPPORTED_CATEGORIES)
        
        # All categories should be empty initially
        for category in SUPPORTED_CATEGORIES:
            assert category in cache.cache
            assert cache.cache[category] == {}
    
    def test_cache_initialization_existing_file(self):
        """Test cache initialization with existing file"""
        # Create existing cache file
        existing_cache = {
            "Phishing": {
                "evil.com": "2025-10-22T00:00:00+00:00"
            },
            "Malicious_Domains": {
                "malware.com": "2025-10-22T00:01:00+00:00"
            }
        }
        
        # Add all other categories as empty
        for category in SUPPORTED_CATEGORIES:
            if category not in existing_cache:
                existing_cache[category] = {}
        
        with open(self.cache_file, 'w') as f:
            json.dump(existing_cache, f)
        
        cache = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        assert cache.cache["Phishing"]["evil.com"] == "2025-10-22T00:00:00+00:00"
        assert cache.cache["Malicious_Domains"]["malware.com"] == "2025-10-22T00:01:00+00:00"
    
    def test_is_domain_recent_within_ttl(self):
        """Test domain recency check within TTL window"""
        cache = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        # Add domain that was used 100 seconds ago (within TTL)
        past_time = datetime.now(timezone.utc) - timedelta(seconds=100)
        cache.cache["Phishing"]["recent.com"] = past_time.isoformat()
        
        assert cache.is_domain_recent("recent.com", "Phishing") is True
    
    def test_is_domain_recent_outside_ttl(self):
        """Test domain recency check outside TTL window"""
        cache = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        # Add domain that was used 400 seconds ago (outside TTL)
        past_time = datetime.now(timezone.utc) - timedelta(seconds=400)
        cache.cache["Phishing"]["old.com"] = past_time.isoformat()
        
        assert cache.is_domain_recent("old.com", "Phishing") is False
    
    def test_is_domain_recent_nonexistent_domain(self):
        """Test domain recency check for non-existent domain"""
        cache = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        assert cache.is_domain_recent("nonexistent.com", "Phishing") is False
    
    def test_is_domain_recent_nonexistent_category(self):
        """Test domain recency check for non-existent category"""
        cache = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        assert cache.is_domain_recent("any.com", "NonExistentCategory") is False
    
    def test_mark_domain_used(self):
        """Test marking domain as used"""
        cache = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        before_time = datetime.now(timezone.utc)
        cache.mark_domain_used("test.com", "Phishing")
        after_time = datetime.now(timezone.utc)
        
        assert "test.com" in cache.cache["Phishing"]
        
        # Check timestamp is reasonable
        timestamp_str = cache.cache["Phishing"]["test.com"]
        timestamp = datetime.fromisoformat(timestamp_str)
        
        assert before_time <= timestamp <= after_time
    
    def test_get_available_domains_filters_recent(self):
        """Test that get_available_domains filters out recent domains"""
        cache = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        # Mark one domain as recent
        recent_time = datetime.now(timezone.utc) - timedelta(seconds=100)
        cache.cache["Phishing"]["recent.com"] = recent_time.isoformat()
        
        # Mark another as old
        old_time = datetime.now(timezone.utc) - timedelta(seconds=400)
        cache.cache["Phishing"]["old.com"] = old_time.isoformat()
        
        domains = ["recent.com", "old.com", "new.com"]
        available = cache.get_available_domains(domains, "Phishing")
        
        # Should filter out recent.com, keep old.com and new.com
        assert "recent.com" not in available
        assert "old.com" in available
        assert "new.com" in available
        assert len(available) == 2
    
    def test_cache_save_and_load_persistence(self):
        """Test cache persistence across save/load operations"""
        cache1 = DomainCache(str(self.cache_file), ttl_seconds=300)
        cache1.mark_domain_used("persist.com", "Phishing")
        cache1.save()
        
        # Create new cache instance with same file
        cache2 = DomainCache(str(self.cache_file), ttl_seconds=300)
        
        assert "persist.com" in cache2.cache["Phishing"]


class TestThreatDomainSampler:
    """Test ThreatDomainSampler main functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.indicators_file = Path(self.temp_dir) / "test_indicators.json"
        self.cache_file = Path(self.temp_dir) / "test_cache.json"
        
        # Create test indicators file
        self.test_indicators = {
            "Phishing": ["phish1.com", "phish2.com", "phish3.com", "phish4.com", "phish5.com"],
            "Malicious_Domains": ["malware1.com", "malware2.com", "malware3.com"],
            "TDS": ["tds1.com", "tds2.com"],
            "Command_&_Control": ["c2-1.com", "c2-2.com", "c2-3.com", "c2-4.com"]
        }
        
        with open(self.indicators_file, 'w') as f:
            json.dump(self.test_indicators, f)
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_sampler_initialization(self):
        """Test sampler initialization"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        assert sampler.indicators == self.test_indicators
        assert len(sampler.category_samples) == len(SUPPORTED_CATEGORIES)
        assert sampler.cache.ttl_seconds == 300
    
    def test_sampler_initialization_missing_indicators(self):
        """Test sampler initialization with missing indicators file"""
        missing_file = Path(self.temp_dir) / "missing.json"
        
        with pytest.raises(FileNotFoundError):
            ThreatDomainSampler(str(missing_file), str(self.cache_file))
    
    def test_sample_domains_basic(self):
        """Test basic domain sampling"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        sample = sampler.sample_domains("Phishing", 3, random_seed=42)
        
        assert sample.category == "Phishing"
        assert len(sample.domains) == 3
        assert sample.sampled_count == 3
        assert all(domain in self.test_indicators["Phishing"] for domain in sample.domains)
        
        # Check timestamp format
        datetime.fromisoformat(sample.sampled_at)  # Should not raise
    
    def test_sample_domains_more_than_available(self):
        """Test sampling more domains than available"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        # TDS only has 2 domains, request 5
        sample = sampler.sample_domains("TDS", 5, random_seed=42)
        
        assert sample.category == "TDS"
        assert len(sample.domains) == 2  # Only 2 available
        assert sample.sampled_count == 2
        assert set(sample.domains) == set(self.test_indicators["TDS"])
    
    def test_sample_domains_unsupported_category(self):
        """Test sampling from unsupported category"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        with pytest.raises(ValueError, match="Unsupported category"):
            sampler.sample_domains("UnsupportedCategory", 3)
    
    def test_sample_domains_category_not_in_indicators(self):
        """Test sampling from category not in indicators file"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        # DNST_Tunneling is supported but not in our test indicators
        sample = sampler.sample_domains("DNST_Tunneling", 3, random_seed=42)
        
        assert sample.category == "DNST_Tunneling"
        assert len(sample.domains) == 0
        assert sample.sampled_count == 0
    
    def test_sample_domains_reproducible_with_seed(self):
        """Test that sampling is reproducible with same seed"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=0  # Disable TTL for this test
        )
        
        sample1 = sampler.sample_domains("Phishing", 3, random_seed=42)
        sample2 = sampler.sample_domains("Phishing", 3, random_seed=42)
        
        assert sample1.domains == sample2.domains
    
    def test_sample_domains_respects_ttl_cache(self):
        """Test that sampling respects TTL cache"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        # First sampling
        sample1 = sampler.sample_domains("Phishing", 3, random_seed=42)
        used_domains = set(sample1.domains)
        
        # Second sampling should avoid recently used domains
        sample2 = sampler.sample_domains("Phishing", 2, random_seed=43)
        new_domains = set(sample2.domains)
        
        # Should have no overlap due to TTL cache
        assert len(used_domains.intersection(new_domains)) == 0
    
    def test_dnst_tunneling_cache_bypass(self):
        """Test that DNST_Tunneling bypasses cache and can reuse domains"""
        # Create test indicators with DNST_Tunneling
        dnst_indicators = {
            "DNST_Tunneling": ["tunnel.test.com"],
            "Phishing": ["phish1.com", "phish2.com", "phish3.com"]
        }
        
        with open(self.indicators_file, 'w') as f:
            json.dump(dnst_indicators, f)
        
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        # Sample DNST_Tunneling multiple times - should repeat the same domain
        sample1 = sampler.sample_domains("DNST_Tunneling", 3)
        sample2 = sampler.sample_domains("DNST_Tunneling", 2)
        
        # Should repeat the single domain
        assert sample1.domains == ["tunnel.test.com", "tunnel.test.com", "tunnel.test.com"]
        assert sample2.domains == ["tunnel.test.com", "tunnel.test.com"]
        
        # Regular category should still respect cache
        phish1 = sampler.sample_domains("Phishing", 2, random_seed=42)
        phish2 = sampler.sample_domains("Phishing", 2, random_seed=43)
        
        # Should be different due to cache filtering
        assert len(set(phish1.domains).intersection(set(phish2.domains))) == 0

    def test_sample_all_categories(self):
        """Test sampling all categories"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        results = sampler.sample_all_categories(2, random_seed=42)
        
        assert len(results) == len(SUPPORTED_CATEGORIES)
        
        # Check categories with indicators
        assert len(results["Phishing"].domains) == 2
        assert len(results["Malicious_Domains"].domains) == 2
        assert len(results["TDS"].domains) == 2
        assert len(results["Command_&_Control"].domains) == 2
        
        # Check categories without indicators  
        assert len(results["DNST_Tunneling"].domains) == 0
    
    def test_sample_specific_categories_subset(self):
        """Test sampling specific subset of categories"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        target_categories = ["Phishing", "TDS"]
        results = sampler.sample_all_categories(
            count_per_category=2,
            categories=target_categories,
            random_seed=42
        )
        
        assert len(results) == 2
        assert "Phishing" in results
        assert "TDS" in results
        assert len(results["Phishing"].domains) == 2
        assert len(results["TDS"].domains) == 2
    
    def test_get_category_domains(self):
        """Test getting domains for specific category"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        # Before sampling
        assert sampler.get_category_domains("Phishing") == []
        
        # After sampling
        sample = sampler.sample_domains("Phishing", 3, random_seed=42)
        domains = sampler.get_category_domains("Phishing")
        
        assert domains == sample.domains
        assert isinstance(domains, list)  # Should be a copy
    
    def test_get_all_sampled_domains(self):
        """Test getting all sampled domains"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        sampler.sample_domains("Phishing", 2, random_seed=42)
        sampler.sample_domains("TDS", 1, random_seed=43)
        
        all_domains = sampler.get_all_sampled_domains()
        
        assert len(all_domains) == len(SUPPORTED_CATEGORIES)
        assert len(all_domains["Phishing"]) == 2
        assert len(all_domains["TDS"]) == 1
        assert len(all_domains["DNST_Tunneling"]) == 0  # Not sampled
    
    def test_export_samples_to_json(self):
        """Test exporting samples to JSON"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        sampler.sample_domains("Phishing", 2, random_seed=42)
        
        export_file = Path(self.temp_dir) / "exported_samples.json"
        sampler.export_samples_to_json(str(export_file))
        
        assert export_file.exists()
        
        with open(export_file) as f:
            data = json.load(f)
        
        assert "export_timestamp" in data
        assert data["ttl_seconds"] == 300
        assert "categories" in data
        assert "Phishing" in data["categories"]
        assert len(data["categories"]["Phishing"]["domains"]) == 2
    
    def test_get_sampling_summary(self):
        """Test getting sampling summary"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        sampler.sample_domains("Phishing", 3, random_seed=42)
        sampler.sample_domains("TDS", 2, random_seed=43)
        
        summary = sampler.get_sampling_summary()
        
        assert summary["total_domains_sampled"] == 5
        assert summary["categories_sampled"] == 2
        assert summary["total_categories"] == len(SUPPORTED_CATEGORIES)
        assert "category_breakdown" in summary
        assert summary["category_breakdown"]["Phishing"]["sampled_count"] == 3
        assert summary["category_breakdown"]["TDS"]["sampled_count"] == 2


class TestConvenienceFunctions:
    """Test convenience functions"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.indicators_file = Path(self.temp_dir) / "test_indicators.json"
        self.cache_file = Path(self.temp_dir) / "test_cache.json"
        
        # Create test indicators
        test_indicators = {
            "Phishing": ["phish1.com", "phish2.com", "phish3.com"],
            "Malicious_Domains": ["malware1.com", "malware2.com"]
        }
        
        with open(self.indicators_file, 'w') as f:
            json.dump(test_indicators, f)
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_sample_domains_for_category_function(self):
        """Test convenience function for single category sampling"""
        domains = sample_domains_for_category(
            category="Phishing",
            count=2,
            indicators_file=str(self.indicators_file),
            cache_file=str(self.cache_file),
            random_seed=42
        )
        
        assert isinstance(domains, list)
        assert len(domains) == 2
        assert all(isinstance(domain, str) for domain in domains)
    
    def test_create_category_objects_function(self):
        """Test convenience function for creating category objects"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file), 
            str(self.cache_file),
            ttl_seconds=300
        )
        
        category_objects = create_category_objects(
            sampler,
            count_per_category=2,
            random_seed=42
        )
        
        assert isinstance(category_objects, dict)
        assert len(category_objects) == len(SUPPORTED_CATEGORIES)
        
        # Check categories with data
        assert "Phishing" in category_objects
        assert isinstance(category_objects["Phishing"], CategorySample)
        assert len(category_objects["Phishing"].domains) == 2
        
        # Check categories without data
        assert "DNST_Tunneling" in category_objects
        assert len(category_objects["DNST_Tunneling"].domains) == 0

    def test_max_sample_constant(self):
        """Test that MAX_SAMPLE constant is properly defined and used"""
        # Check constant value
        assert MAX_SAMPLE == 50
        assert isinstance(MAX_SAMPLE, int)
        
        # Create separate cache files to avoid TTL conflicts
        cache_file_1 = Path(self.temp_dir) / "cache1.json"
        cache_file_2 = Path(self.temp_dir) / "cache2.json"
        
        # Test with explicit MAX_SAMPLE
        sampler1 = ThreatDomainSampler(
            str(self.indicators_file), 
            str(cache_file_1),
            ttl_seconds=300
        )
        results_explicit = create_category_objects(sampler1, count_per_category=MAX_SAMPLE, random_seed=42)
        
        # Test with default (should be same as MAX_SAMPLE)
        sampler2 = ThreatDomainSampler(
            str(self.indicators_file), 
            str(cache_file_2),
            ttl_seconds=300
        )
        results_default = create_category_objects(sampler2, random_seed=42)
        
        # Should be the same since default should use MAX_SAMPLE
        # (Note: comparing counts since domains might be different due to cache state)
        for category in SUPPORTED_CATEGORIES:
            if category in sampler1.indicators and len(sampler1.indicators[category]) >= MAX_SAMPLE:
                # Only test categories that have enough domains for MAX_SAMPLE
                assert len(results_explicit[category].domains) == len(results_default[category].domains) == MAX_SAMPLE


class TestErrorHandling:
    """Test error handling and edge cases"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_cache_with_corrupted_json(self):
        """Test cache handling with corrupted JSON file"""
        cache_file = Path(self.temp_dir) / "corrupted_cache.json"
        
        # Create corrupted JSON
        with open(cache_file, 'w') as f:
            f.write('{"invalid": json content}')
        
        # Should handle gracefully and create new cache
        cache = DomainCache(str(cache_file), ttl_seconds=300)
        
        assert len(cache.cache) == len(SUPPORTED_CATEGORIES)
        assert all(cache.cache[cat] == {} for cat in SUPPORTED_CATEGORIES)
    
    def test_cache_with_invalid_timestamp(self):
        """Test cache handling with invalid timestamp"""
        cache_file = Path(self.temp_dir) / "invalid_timestamp_cache.json"
        
        # Create cache with invalid timestamp
        invalid_cache = {category: {} for category in SUPPORTED_CATEGORIES}
        invalid_cache["Phishing"]["test.com"] = "invalid-timestamp"
        
        with open(cache_file, 'w') as f:
            json.dump(invalid_cache, f)
        
        cache = DomainCache(str(cache_file), ttl_seconds=300)
        
        # Should handle invalid timestamp gracefully
        assert cache.is_domain_recent("test.com", "Phishing") is False
    
    def test_export_to_invalid_directory(self):
        """Test export to invalid/non-writable directory"""
        indicators_file = Path(self.temp_dir) / "indicators.json"
        with open(indicators_file, 'w') as f:
            json.dump({"Phishing": ["test.com"]}, f)
        
        sampler = ThreatDomainSampler(str(indicators_file))
        
        # Try to export to non-existent directory (should create it)
        export_file = Path(self.temp_dir) / "new_dir" / "exported.json"
        sampler.export_samples_to_json(str(export_file))
        
        # Should have created the directory and file
        assert export_file.exists()


class TestIntegrationScenarios:
    """Test realistic integration scenarios"""
    
    def setup_method(self):
        """Setup realistic test environment"""
        self.temp_dir = tempfile.mkdtemp()
        self.indicators_file = Path(self.temp_dir) / "indicators.json"
        self.cache_file = Path(self.temp_dir) / "cache.json"
        
        # Create realistic indicators
        self.realistic_indicators = {}
        for category in SUPPORTED_CATEGORIES:
            # Create 100 domains per category
            domains = [f"{category.lower()}-{i}.com" for i in range(100)]
            self.realistic_indicators[category] = domains
        
        with open(self.indicators_file, 'w') as f:
            json.dump(self.realistic_indicators, f)
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_realistic_sampling_workflow(self):
        """Test realistic sampling workflow with multiple categories"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        # Sample 50 domains per category
        results = sampler.sample_all_categories(50, random_seed=42)
        
        # Verify all categories have samples
        for category in SUPPORTED_CATEGORIES:
            assert category in results
            assert len(results[category].domains) == 50
            assert results[category].sampled_count == 50
        
        # Test summary
        summary = sampler.get_sampling_summary()
        assert summary["total_domains_sampled"] == 50 * len(SUPPORTED_CATEGORIES)
        assert summary["categories_sampled"] == len(SUPPORTED_CATEGORIES)
    
    def test_ttl_filtering_over_time(self):
        """Test TTL filtering behavior over multiple sampling rounds"""
        sampler = ThreatDomainSampler(
            str(self.indicators_file),
            str(self.cache_file),
            ttl_seconds=1  # Very short TTL for testing
        )
        
        # First round of sampling
        results1 = sampler.sample_domains("Phishing", 10, random_seed=42)
        first_domains = set(results1.domains)
        
        # Second round immediately (should get different domains)
        results2 = sampler.sample_domains("Phishing", 10, random_seed=43)
        second_domains = set(results2.domains)
        
        # Should have no overlap due to TTL
        assert len(first_domains.intersection(second_domains)) == 0
        
        # Wait for TTL to expire
        import time
        time.sleep(1.1)
        
        # Third round after TTL (can reuse domains)
        results3 = sampler.sample_domains("Phishing", 10, random_seed=42)
        third_domains = set(results3.domains)
        
        # Should be able to get domains again (may have overlap)
        # With same seed, should get same results as first round
        assert third_domains == first_domains
    
    def test_exhaustive_sampling_scenario(self):
        """Test scenario where we exhaust available domains"""
        # Create category with only 5 domains
        small_indicators = {
            "Phishing": ["p1.com", "p2.com", "p3.com", "p4.com", "p5.com"]
        }
        
        small_indicators_file = Path(self.temp_dir) / "small_indicators.json"
        with open(small_indicators_file, 'w') as f:
            json.dump(small_indicators, f)
        
        sampler = ThreatDomainSampler(
            str(small_indicators_file),
            str(self.cache_file),
            ttl_seconds=300
        )
        
        # Sample all 5 domains
        results1 = sampler.sample_domains("Phishing", 5, random_seed=42)
        assert len(results1.domains) == 5
        
        # Try to sample more - should get 0 due to TTL
        results2 = sampler.sample_domains("Phishing", 3, random_seed=43)
        assert len(results2.domains) == 0  # All domains are in TTL cache


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])