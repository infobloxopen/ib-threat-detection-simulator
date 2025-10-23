"""
Threat Detection Simulator v2 - Domain Digger Module

This module handles concurrent DNS resolution (dig) operations for sampled domains.
It takes category objects from the sampler and performs DNS queries for each domain,
tracking successful and failed resolutions separately.

Key features:
- Concurrent DNS resolution per category 
- DNS server auto-detection with fallback logic
- Detailed error tracking and reporting
- Extends CategorySample with dig results
"""

import subprocess
import logging
import asyncio
import concurrent.futures
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from .sampler import CategorySample

logger = logging.getLogger(__name__)

@dataclass
class DigResult:
    """Result of a single dig operation"""
    domain: str
    status: str  # 'success' or 'error'
    output: str
    error: str
    dns_server: str
    command: str
    execution_time: float
    timestamp: str

@dataclass 
class CategoryDigResult:
    """Extended CategorySample with dig results"""
    category: str
    domains: List[str]
    sampled_count: int
    sampled_at: str
    
    # New fields for dig results
    successful_domains: List[str] = field(default_factory=list)
    failed_domains: List[Dict] = field(default_factory=list)  # List of {domain, error, command}
    dig_results: Dict[str, DigResult] = field(default_factory=dict)
    dig_summary: Dict = field(default_factory=dict)
    
    @classmethod
    def from_category_sample(cls, sample: CategorySample) -> 'CategoryDigResult':
        """Create CategoryDigResult from CategorySample"""
        return cls(
            category=sample.category,
            domains=sample.domains,
            sampled_count=sample.sampled_count,
            sampled_at=sample.sampled_at
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary, handling DigResult objects"""
        result = {
            'category': self.category,
            'domains': self.domains,
            'sampled_count': self.sampled_count,
            'sampled_at': self.sampled_at,
            'successful_domains': self.successful_domains,
            'failed_domains': self.failed_domains,
            'dig_summary': self.dig_summary
        }
        
        # Convert DigResult objects to dicts
        result['dig_results'] = {
            domain: dig_result.__dict__ if hasattr(dig_result, '__dict__') else dig_result
            for domain, dig_result in self.dig_results.items()
        }
        
        return result

class DomainDigger:
    """Handles concurrent DNS resolution for domain categories"""
    
    def __init__(self, dns_server: Optional[str] = None, timeout: int = 10, max_workers: int = 10):
        """
        Initialize the domain digger
        
        Args:
            dns_server: DNS server to use (None for auto-detection)
            timeout: Timeout for dig operations in seconds
            max_workers: Maximum concurrent workers per category
        """
        self.dns_server = dns_server or self._detect_best_dns_server()
        self.timeout = timeout
        self.max_workers = max_workers
        
        logger.info(f"🌐 Domain Digger initialized with DNS server: {self.dns_server}")
        logger.info(f"⚙️ Timeout: {self.timeout}s, Max workers: {self.max_workers}")
    
    def _detect_best_dns_server(self) -> str:
        """
        Detect the best DNS server to use by testing system default first, then fallback to GCP DNS.
        
        Returns:
            str: The best DNS server to use ('system' for default, or IP address)
        """
        # Test 1: Try system default DNS (no @ specified)
        try:
            logger.info("🔍 Testing system default DNS resolver...")
            result = subprocess.run(['dig', 'example.com', '+short'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                logger.info("✅ System default DNS working correctly")
                return 'system'
            else:
                logger.warning(f"⚠️ System default DNS failed: {result.stderr.strip()}")
        except Exception as e:
            logger.warning(f"⚠️ System default DNS test failed: {e}")
        
        # Test 2: Fallback to GCP metadata server DNS
        try:
            logger.info("🔍 Testing fallback DNS (169.254.169.254)...")
            result = subprocess.run(['dig', '@169.254.169.254', 'example.com', '+short'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                logger.info("✅ Fallback DNS (169.254.169.254) working correctly")
                return '169.254.169.254'
            else:
                logger.warning(f"⚠️ Fallback DNS failed: {result.stderr.strip()}")
        except Exception as e:
            logger.warning(f"⚠️ Fallback DNS test failed: {e}")
        
        # If both fail, still return system default as last resort
        logger.error("❌ Both DNS tests failed, using system default as last resort")
        return 'system'
    
    def _execute_dig_single(self, domain: str) -> DigResult:
        """
        Execute dig command for a single domain with error logging and fallback logic.
        
        Args:
            domain: Domain to query
            
        Returns:
            DigResult: Result with status, output, and error information
        """
        start_time = datetime.now(timezone.utc)
        
        # Build dig command
        if self.dns_server == 'system':
            dig_cmd = ['dig', domain, '+short']
            server_desc = "system default"
        else:
            dig_cmd = ['dig', f'@{self.dns_server}', domain, '+short']
            server_desc = self.dns_server
        
        try:
            result = subprocess.run(dig_cmd, capture_output=True, text=True, timeout=self.timeout)
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            if result.returncode == 0:
                return DigResult(
                    domain=domain,
                    status="success",
                    output=result.stdout.strip(),
                    error="",
                    dns_server=self.dns_server,
                    command=' '.join(dig_cmd),
                    execution_time=execution_time,
                    timestamp=start_time.isoformat()
                )
            else:
                # Log the failure
                error_msg = result.stderr.strip()
                logger.debug(f"🔍 DNS query failed for {domain} using {server_desc}: {error_msg}")
                
                # Check for common error patterns
                if "timed out" in error_msg.lower():
                    logger.debug(f"⏰ DNS timeout for {domain} on {server_desc}")
                elif "connection refused" in error_msg.lower():
                    logger.debug(f"🚫 DNS connection refused for {domain} on {server_desc}")
                
                return DigResult(
                    domain=domain,
                    status="error",
                    output="",
                    error=error_msg,
                    dns_server=self.dns_server,
                    command=' '.join(dig_cmd),
                    execution_time=execution_time,
                    timestamp=start_time.isoformat()
                )
                
        except subprocess.TimeoutExpired:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            error_msg = f"DNS query timeout after {self.timeout} seconds"
            logger.debug(f"⏰ {error_msg} for {domain} using {server_desc}")
            return DigResult(
                domain=domain,
                status="error",
                output="",
                error=error_msg,
                dns_server=self.dns_server,
                command=' '.join(dig_cmd),
                execution_time=execution_time,
                timestamp=start_time.isoformat()
            )
        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            error_msg = str(e)
            logger.debug(f"❌ DNS query exception for {domain} using {server_desc}: {error_msg}")
            return DigResult(
                domain=domain,
                status="error",
                output="",
                error=error_msg,
                dns_server=self.dns_server,
                command=' '.join(dig_cmd),
                execution_time=execution_time,
                timestamp=start_time.isoformat()
            )
    
    def _dig_category_domains(self, category_sample: CategorySample) -> CategoryDigResult:
        """
        Perform concurrent dig operations for all domains in a category
        
        Args:
            category_sample: CategorySample object with domains to dig
            
        Returns:
            CategoryDigResult: Extended result with dig information
        """
        category_result = CategoryDigResult.from_category_sample(category_sample)
        
        if not category_sample.domains:
            logger.info(f"📭 No domains to dig for category: {category_sample.category}")
            category_result.dig_summary = {
                'total_domains': 0,
                'successful_count': 0,
                'failed_count': 0,
                'success_rate': 0.0,
                'total_execution_time': 0.0
            }
            return category_result
        
        logger.info(f"🔍 Starting dig operations for {category_sample.category}: {len(category_sample.domains)} domains")
        
        # Use ThreadPoolExecutor for concurrent dig operations
        dig_results = {}
        successful_domains = []
        failed_domains = []
        total_execution_time = 0.0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all dig operations
            future_to_domain = {
                executor.submit(self._execute_dig_single, domain): domain 
                for domain in category_sample.domains
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    dig_result = future.result()
                    dig_results[domain] = dig_result
                    total_execution_time += dig_result.execution_time
                    
                    if dig_result.status == "success":
                        successful_domains.append(domain)
                        logger.debug(f"✅ {domain}: {dig_result.output}")
                    else:
                        failed_domains.append({
                            'domain': domain,
                            'error': dig_result.error,
                            'command': dig_result.command
                        })
                        logger.debug(f"❌ {domain}: {dig_result.error}")
                        
                except Exception as e:
                    logger.error(f"❌ Unexpected error processing {domain}: {e}")
                    failed_domains.append({
                        'domain': domain,
                        'error': str(e),
                        'command': 'unknown'
                    })
        
        # Update category result
        category_result.successful_domains = successful_domains
        category_result.failed_domains = failed_domains
        category_result.dig_results = dig_results
        
        # Calculate summary statistics
        total_domains = len(category_sample.domains)
        successful_count = len(successful_domains)
        failed_count = len(failed_domains)
        success_rate = (successful_count / total_domains * 100) if total_domains > 0 else 0.0
        
        category_result.dig_summary = {
            'total_domains': total_domains,
            'successful_count': successful_count,
            'failed_count': failed_count,
            'success_rate': success_rate,
            'total_execution_time': total_execution_time,
            'average_execution_time': total_execution_time / total_domains if total_domains > 0 else 0.0
        }
        
        logger.info(f"📊 {category_sample.category} dig completed: "
                   f"{successful_count}/{total_domains} successful ({success_rate:.1f}%)")
        
        if failed_count > 0:
            logger.warning(f"⚠️ {category_sample.category}: {failed_count} domains failed DNS resolution")
        
        return category_result
    
    def dig_categories(self, category_samples: Dict[str, CategorySample]) -> Dict[str, CategoryDigResult]:
        """
        Perform concurrent dig operations for multiple categories
        
        Args:
            category_samples: Dictionary of category name to CategorySample objects
            
        Returns:
            Dictionary of category name to CategoryDigResult objects
        """
        logger.info(f"🚀 Starting concurrent dig operations for {len(category_samples)} categories")
        
        results = {}
        
        # Use ThreadPoolExecutor for concurrent category processing
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(category_samples)) as executor:
            # Submit dig operations for each category
            future_to_category = {
                executor.submit(self._dig_category_domains, sample): category
                for category, sample in category_samples.items()
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_category):
                category = future_to_category[future]
                try:
                    result = future.result()
                    results[category] = result
                    logger.info(f"✅ Completed dig operations for {category}")
                except Exception as e:
                    logger.error(f"❌ Error processing category {category}: {e}")
                    # Create empty result for failed category
                    results[category] = CategoryDigResult.from_category_sample(category_samples[category])
        
        # Log overall summary
        total_domains = sum(len(sample.domains) for sample in category_samples.values())
        total_successful = sum(len(result.successful_domains) for result in results.values())
        total_failed = sum(len(result.failed_domains) for result in results.values())
        overall_success_rate = (total_successful / total_domains * 100) if total_domains > 0 else 0.0
        
        logger.info(f"🎯 Overall dig summary: {total_successful}/{total_domains} successful ({overall_success_rate:.1f}%)")
        
        return results

# Convenience functions
def dig_domains_for_categories(category_samples: Dict[str, CategorySample], 
                              dns_server: Optional[str] = None,
                              timeout: int = 10,
                              max_workers: int = 10) -> Dict[str, CategoryDigResult]:
    """
    Convenience function to perform dig operations for category samples
    
    Args:
        category_samples: Dictionary of CategorySample objects
        dns_server: DNS server to use (None for auto-detection)
        timeout: Timeout for dig operations
        max_workers: Maximum concurrent workers
        
    Returns:
        Dictionary of CategoryDigResult objects
    """
    digger = DomainDigger(dns_server=dns_server, timeout=timeout, max_workers=max_workers)
    return digger.dig_categories(category_samples)

if __name__ == "__main__":
    # Example usage
    import logging
    from .sampler import ThreatDomainSampler, MAX_SAMPLE
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Sample some domains
    sampler = ThreatDomainSampler()
    categories = sampler.sample_all_categories(5)  # Sample 5 domains per category
    
    # Dig the domains
    digger = DomainDigger()
    results = digger.dig_categories(categories)
    
    # Print summary
    print(f"\n📊 Dig Results Summary:")
    for category, result in results.items():
        summary = result.dig_summary
        print(f"  {category}: {summary['successful_count']}/{summary['total_domains']} "
              f"({summary['success_rate']:.1f}%) successful")
