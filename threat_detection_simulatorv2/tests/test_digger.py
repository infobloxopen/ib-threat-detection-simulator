"""
Unit tests for the Threat Detection Simulator v2 - Domain Digger Module

Tests cover:
1. DNS server detection and fallback logic
2. Single domain dig operations
3. Category-level concurrent dig operations
4. Error handling and timeout scenarios
5. Data structure conversions
6. Integration with sampler
"""

import json
import pytest
import tempfile
import shutil
from unittest.mock import patch, MagicMock
from pathlib import Path
import subprocess

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from utils.digger import (
    DomainDigger,
    DigResult,
    CategoryDigResult,
    dig_domains_for_categories
)
from utils.sampler import CategorySample, ThreatDomainSampler

class TestDigResult:
    """Test DigResult data structure"""
    
    def test_dig_result_creation(self):
        """Test creating DigResult objects"""
        result = DigResult(
            domain="test.com",
            status="success",
            output="1.2.3.4",
            error="",
            dns_server="system",
            command="dig test.com +short",
            execution_time=0.5,
            timestamp="2025-10-22T00:00:00+00:00"
        )
        
        assert result.domain == "test.com"
        assert result.status == "success"
        assert result.output == "1.2.3.4"
        assert result.execution_time == 0.5

class TestCategoryDigResult:
    """Test CategoryDigResult data structure"""
    
    def test_category_dig_result_creation(self):
        """Test creating CategoryDigResult objects"""
        result = CategoryDigResult(
            category="Phishing",
            domains=["test1.com", "test2.com"],
            sampled_count=2,
            sampled_at="2025-10-22T00:00:00+00:00"
        )
        
        assert result.category == "Phishing"
        assert len(result.domains) == 2
        assert len(result.successful_domains) == 0
        assert len(result.failed_domains) == 0
    
    def test_from_category_sample(self):
        """Test creating CategoryDigResult from CategorySample"""
        sample = CategorySample(
            category="Phishing",
            domains=["test1.com", "test2.com"],
            sampled_count=2,
            sampled_at="2025-10-22T00:00:00+00:00"
        )
        
        result = CategoryDigResult.from_category_sample(sample)
        
        assert result.category == sample.category
        assert result.domains == sample.domains
        assert result.sampled_count == sample.sampled_count
        assert result.sampled_at == sample.sampled_at
    
    def test_to_dict(self):
        """Test converting CategoryDigResult to dictionary"""
        result = CategoryDigResult(
            category="Phishing",
            domains=["test.com"],
            sampled_count=1,
            sampled_at="2025-10-22T00:00:00+00:00",
            successful_domains=["test.com"],
            failed_domains=[],
            dig_summary={"total_domains": 1, "successful_count": 1}
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["category"] == "Phishing"
        assert result_dict["successful_domains"] == ["test.com"]
        assert result_dict["dig_summary"]["total_domains"] == 1

class TestDomainDigger:
    """Test DomainDigger functionality"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    @patch('subprocess.run')
    def test_dns_server_detection_system_works(self, mock_run):
        """Test DNS server detection when system DNS works"""
        # Mock successful system DNS
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="93.184.216.34\n",
            stderr=""
        )
        
        digger = DomainDigger()
        assert digger.dns_server == "system"
    
    @patch('subprocess.run')
    def test_dns_server_detection_fallback(self, mock_run):
        """Test DNS server detection with fallback"""
        # Mock system DNS failure, fallback success
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="DNS error"),  # System DNS fails
            MagicMock(returncode=0, stdout="93.184.216.34\n", stderr="")  # Fallback works
        ]
        
        digger = DomainDigger()
        assert digger.dns_server == "169.254.169.254"
    
    @patch('subprocess.run')
    def test_dns_server_detection_both_fail(self, mock_run):
        """Test DNS server detection when both fail"""
        # Mock both DNS failures
        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="System DNS error"),  # System fails
            MagicMock(returncode=1, stdout="", stderr="Fallback DNS error")  # Fallback fails
        ]
        
        digger = DomainDigger()
        assert digger.dns_server == "system"  # Falls back to system as last resort
    
    @patch('subprocess.run')
    def test_execute_dig_single_success(self, mock_run):
        """Test successful single dig operation"""
        # Mock successful dig
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="1.2.3.4\n",
            stderr=""
        )
        
        digger = DomainDigger(dns_server="system")
        result = digger._execute_dig_single("test.com")
        
        assert result.domain == "test.com"
        assert result.status == "success"
        assert result.output == "1.2.3.4"
        assert result.error == ""
        assert "dig test.com +short" in result.command
    
    @patch('subprocess.run')
    def test_execute_dig_single_failure(self, mock_run):
        """Test failed single dig operation"""
        # Mock failed dig
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="NXDOMAIN"
        )
        
        digger = DomainDigger(dns_server="system")
        result = digger._execute_dig_single("nonexistent.com")
        
        assert result.domain == "nonexistent.com"
        assert result.status == "error"
        assert result.output == ""
        assert result.error == "NXDOMAIN"
    
    @patch('subprocess.run')
    def test_execute_dig_single_timeout(self, mock_run):
        """Test dig operation timeout"""
        # Mock timeout
        mock_run.side_effect = subprocess.TimeoutExpired(['dig'], 10)
        
        digger = DomainDigger(dns_server="system", timeout=1)
        result = digger._execute_dig_single("slow.com")
        
        assert result.domain == "slow.com"
        assert result.status == "error"
        assert "timeout" in result.error.lower()
    
    def test_dig_category_domains_empty(self):
        """Test digging category with no domains"""
        sample = CategorySample(
            category="Empty",
            domains=[],
            sampled_count=0,
            sampled_at="2025-10-22T00:00:00+00:00"
        )
        
        digger = DomainDigger()
        result = digger._dig_category_domains(sample)
        
        assert result.category == "Empty"
        assert len(result.successful_domains) == 0
        assert len(result.failed_domains) == 0
        assert result.dig_summary["total_domains"] == 0
        assert result.dig_summary["success_rate"] == 0.0
    
    @patch('utils.digger.DomainDigger._execute_dig_single')
    def test_dig_category_domains_mixed_results(self, mock_dig):
        """Test digging category with mixed success/failure results"""
        # Mock mixed results
        mock_dig.side_effect = [
            DigResult("success.com", "success", "1.2.3.4", "", "system", "dig cmd", 0.1, "2025-10-22T00:00:00+00:00"),
            DigResult("fail.com", "error", "", "NXDOMAIN", "system", "dig cmd", 0.2, "2025-10-22T00:00:00+00:00")
        ]
        
        sample = CategorySample(
            category="Mixed",
            domains=["success.com", "fail.com"],
            sampled_count=2,
            sampled_at="2025-10-22T00:00:00+00:00"
        )
        
        digger = DomainDigger()
        result = digger._dig_category_domains(sample)
        
        assert result.category == "Mixed"
        assert len(result.successful_domains) == 1
        assert len(result.failed_domains) == 1
        assert "success.com" in result.successful_domains
        assert result.failed_domains[0]["domain"] == "fail.com"
        assert result.dig_summary["total_domains"] == 2
        assert result.dig_summary["successful_count"] == 1
        assert result.dig_summary["failed_count"] == 1
        assert result.dig_summary["success_rate"] == 50.0
    
    @patch('utils.digger.DomainDigger._dig_category_domains')
    def test_dig_categories_multiple(self, mock_dig_category):
        """Test digging multiple categories concurrently"""
        # Mock category results
        def mock_category_result(sample):
            result = CategoryDigResult.from_category_sample(sample)
            result.successful_domains = sample.domains[:1]  # First domain succeeds
            result.failed_domains = [{"domain": d, "error": "test error", "command": "test cmd"} for d in sample.domains[1:]]
            result.dig_summary = {
                "total_domains": len(sample.domains),
                "successful_count": len(result.successful_domains),
                "failed_count": len(result.failed_domains),
                "success_rate": len(result.successful_domains) / len(sample.domains) * 100 if sample.domains else 0
            }
            return result
        
        mock_dig_category.side_effect = mock_category_result
        
        samples = {
            "Cat1": CategorySample("Cat1", ["d1.com", "d2.com"], 2, "2025-10-22T00:00:00+00:00"),
            "Cat2": CategorySample("Cat2", ["d3.com"], 1, "2025-10-22T00:00:00+00:00")
        }
        
        digger = DomainDigger()
        results = digger.dig_categories(samples)
        
        assert len(results) == 2
        assert "Cat1" in results
        assert "Cat2" in results
        assert results["Cat1"].dig_summary["success_rate"] == 50.0
        assert results["Cat2"].dig_summary["success_rate"] == 100.0

class TestConvenienceFunctions:
    """Test convenience functions"""
    
    @patch('utils.digger.DomainDigger')
    def test_dig_domains_for_categories(self, mock_digger_class):
        """Test convenience function for digging categories"""
        # Mock digger instance
        mock_digger = MagicMock()
        mock_digger_class.return_value = mock_digger
        mock_digger.dig_categories.return_value = {"Test": "result"}
        
        samples = {"Test": CategorySample("Test", ["test.com"], 1, "2025-10-22T00:00:00+00:00")}
        result = dig_domains_for_categories(samples, dns_server="8.8.8.8", timeout=5)
        
        # Verify digger was created with correct parameters
        mock_digger_class.assert_called_once_with(dns_server="8.8.8.8", timeout=5, max_workers=10)
        mock_digger.dig_categories.assert_called_once_with(samples)
        assert result == {"Test": "result"}

class TestIntegrationScenarios:
    """Test integration scenarios"""
    
    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create test indicators file
        self.indicators_file = Path(self.temp_dir) / "test_indicators.json"
        test_indicators = {
            "Phishing": ["google.com", "example.com"],  # Use real domains for actual resolution
            "TestCategory": ["test1.com", "test2.com"]
        }
        
        with open(self.indicators_file, 'w') as f:
            json.dump(test_indicators, f)
    
    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir)
    
    def test_end_to_end_integration(self):
        """Test complete sampler -> digger integration"""
        # Create sampler
        cache_file = Path(self.temp_dir) / "cache.json"
        sampler = ThreatDomainSampler(str(self.indicators_file), str(cache_file), ttl_seconds=300)
        
        # Sample domains
        samples = sampler.sample_all_categories(1)  # Sample 1 domain per category
        
        # Dig domains
        results = dig_domains_for_categories(samples, timeout=5)
        
        # Verify results structure
        assert isinstance(results, dict)
        for category, result in results.items():
            assert isinstance(result, CategoryDigResult)
            assert result.category == category
            assert hasattr(result, 'dig_summary')
            assert 'total_domains' in result.dig_summary
            assert 'successful_count' in result.dig_summary
            assert 'failed_count' in result.dig_summary
            assert 'success_rate' in result.dig_summary
    
    @patch('subprocess.run')
    def test_real_domain_resolution(self, mock_run):
        """Test with realistic domain resolution scenarios"""
        # Mock some domains succeeding, others failing
        def mock_subprocess(cmd, **kwargs):
            domain = cmd[1] if cmd[1] != "+short" else cmd[2]  # Extract domain from command
            
            if "google.com" in ' '.join(cmd):
                return MagicMock(returncode=0, stdout="142.250.191.14\n", stderr="")
            elif "nonexistent-test-domain-12345.com" in ' '.join(cmd):
                return MagicMock(returncode=1, stdout="", stderr="NXDOMAIN")
            else:
                return MagicMock(returncode=0, stdout="1.2.3.4\n", stderr="")
        
        mock_run.side_effect = mock_subprocess
        
        # Create sample with mixed domains
        sample = CategorySample(
            category="Mixed",
            domains=["google.com", "nonexistent-test-domain-12345.com"],
            sampled_count=2,
            sampled_at="2025-10-22T00:00:00+00:00"
        )
        
        digger = DomainDigger()
        result = digger._dig_category_domains(sample)
        
        # Should have one success, one failure
        assert len(result.successful_domains) == 1
        assert len(result.failed_domains) == 1
        assert "google.com" in result.successful_domains
        assert result.failed_domains[0]["domain"] == "nonexistent-test-domain-12345.com"
        assert result.dig_summary["success_rate"] == 50.0