"""
Threat Detection Simulator v2 - Threat Event Fetcher Module

This module handles fetching threat detection event logs for successfully resolved domains.
It takes CategoryDigResult objects from the digger and searches for threat detection events,
calculating detection rates and providing detailed threat analysis.

Key features:
- Local threat log simulation (file-based) for testing
- GCP Cloud Logging integration for real threat detection logs
- Detection rate calculation based on successfully digged domains
- Detailed threat event analysis and filtering
- Extends CategoryDigResult with threat detection information
"""

import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
from .digger import CategoryDigResult

logger = logging.getLogger(__name__)

# Constants
TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

@dataclass
class ThreatEvent:
    """Individual threat detection event"""
    timestamp: str
    query_name: str
    threat_id: str
    threat_feed: str
    vm_instance_id: str
    source_ip: str
    query_type: str
    response_code: str
    raw_entry: Dict = field(default_factory=dict)

@dataclass
class CategoryThreatResult:
    """Extended CategoryDigResult with threat detection results"""
    category: str
    domains: List[str]
    sampled_count: int
    sampled_at: str
    
    # Dig results (from digger)
    successful_domains: List[str] = field(default_factory=list)
    failed_domains: List[Dict] = field(default_factory=list)
    dig_results: Dict = field(default_factory=dict)
    dig_summary: Dict = field(default_factory=dict)
    
    # New fields for threat detection results
    threat_events: List[ThreatEvent] = field(default_factory=list)
    detected_domains: List[str] = field(default_factory=list)  # Domains with threat events
    undetected_domains: List[str] = field(default_factory=list)  # Successfully digged but no threats
    threat_summary: Dict = field(default_factory=dict)
    
    @classmethod
    def from_category_dig_result(cls, dig_result: CategoryDigResult) -> 'CategoryThreatResult':
        """Create CategoryThreatResult from CategoryDigResult"""
        return cls(
            category=dig_result.category,
            domains=dig_result.domains,
            sampled_count=dig_result.sampled_count,
            sampled_at=dig_result.sampled_at,
            successful_domains=dig_result.successful_domains,
            failed_domains=dig_result.failed_domains,
            dig_results=dig_result.dig_results,
            dig_summary=dig_result.dig_summary
        )
    
    def to_dict(self) -> Dict:
        """Convert to dictionary, handling ThreatEvent objects"""
        result = {
            'category': self.category,
            'domains': self.domains,
            'sampled_count': self.sampled_count,
            'sampled_at': self.sampled_at,
            'successful_domains': self.successful_domains,
            'failed_domains': self.failed_domains,
            'dig_summary': self.dig_summary,
            'detected_domains': self.detected_domains,
            'undetected_domains': self.undetected_domains,
            'threat_summary': self.threat_summary
        }
        
        # Convert ThreatEvent objects to dicts
        result['threat_events'] = [
            event.__dict__ if hasattr(event, '__dict__') else event
            for event in self.threat_events
        ]
        
        # Convert dig_results if needed
        result['dig_results'] = {
            domain: dig_result.__dict__ if hasattr(dig_result, '__dict__') else dig_result
            for domain, dig_result in self.dig_results.items()
        }
        
        return result

class ThreatEventFetcher:
    """Fetches threat detection events for successfully resolved domains"""
    
    def __init__(self, mode: str = "simulation", 
                 project_id: Optional[str] = None,
                 vm_instance_id: Optional[str] = None,
                 vm_zone: Optional[str] = None,
                 hours_back: float = 2.0,
                 max_entries: int = 5000):
        """
        Initialize the threat event fetcher
        
        Args:
            mode: "simulation" for local file-based testing, "gcp" for real GCP logs
            project_id: GCP project ID (required for GCP mode)
            vm_instance_id: VM instance ID (required for GCP mode)
            vm_zone: VM zone (required for GCP mode)
            hours_back: How many hours back to search for logs
            max_entries: Maximum number of log entries to retrieve
        """
        self.mode = mode
        self.project_id = project_id
        self.vm_instance_id = vm_instance_id
        self.vm_zone = vm_zone
        self.hours_back = hours_back
        self.max_entries = max_entries
        
        logger.info(f"🎯 ThreatEventFetcher initialized in {mode} mode")
        
        if mode == "gcp":
            if not all([project_id, vm_instance_id, vm_zone]):
                raise ValueError("GCP mode requires project_id, vm_instance_id, and vm_zone")
            logger.info(f"🌐 GCP config: project={project_id}, vm={vm_instance_id}, zone={vm_zone}")
        else:
            logger.info("🧪 Using simulation mode with local threat event generation")
    
    def _generate_simulated_threat_events(self, domains: List[str], category: str) -> List[ThreatEvent]:
        """
        Generate simulated threat events for testing purposes
        
        Args:
            domains: List of domains to simulate threats for
            category: Category name for threat type mapping
            
        Returns:
            List of simulated ThreatEvent objects
        """
        threat_events = []
        
        # Map categories to threat IDs (based on v1 analysis)
        threat_id_mapping = {
            "Phishing": "Phishing",
            "Lookalikes": "Phishing", 
            "TDS": "Malicious_Generic",
            "Command_&_Control": "Command_Control",
            "DGAS_&_RDGAS": "DGA_Generic",
            "Emerging_Domains": "Malicious_Generic",
            "High_Risk": "Malicious_Generic",
            "Malicious_Domains": "Malicious_Generic",
            "DGA_Malware": "DGA_Generic",
            "DNST_Tunneling": "TI-DNST"
        }
        
        threat_id = threat_id_mapping.get(category, "Malicious_Generic")
        
        # Simulate threat detection for most domains (high detection rate for testing)
        detected_count = max(1, int(len(domains) * 0.85))  # 85% detection rate
        detected_domains = domains[:detected_count]
        
        for i, domain in enumerate(detected_domains):
            timestamp = (datetime.now(timezone.utc) - timedelta(minutes=i*2)).isoformat()
            
            threat_event = ThreatEvent(
                timestamp=timestamp,
                query_name=domain,
                threat_id=threat_id,
                threat_feed="BloxOne_Threat_Feed",
                vm_instance_id=self.vm_instance_id or "test-vm-instance",
                source_ip="10.0.0.100",
                query_type="A",
                response_code="NOERROR",
                raw_entry={
                    "jsonPayload": {
                        "dnsQuery": {
                            "queryName": domain,
                            "vmInstanceId": self.vm_instance_id or "test-vm-instance",
                            "sourceIP": "10.0.0.100",
                            "queryType": "A",
                            "responseCode": "NOERROR"
                        },
                        "threatInfo": {
                            "threatId": threat_id,
                            "threatFeed": "BloxOne_Threat_Feed",
                            "threatIndicator": domain
                        }
                    }
                }
            )
            threat_events.append(threat_event)
        
        logger.info(f"🧪 Simulated {len(threat_events)} threat events for {category}")
        return threat_events
    
    def _build_domain_filter(self, domains: List[str]) -> str:
        """Build domain filter conditions for GCP Cloud Logging"""
        domain_conditions = []
        for domain in domains:
            # Standard query name filters
            domain_conditions.append(f'jsonPayload.dnsQuery.queryName="{domain}"')
            domain_conditions.append(f'jsonPayload.dnsQuery.queryName="{domain}."')
            # Also check threat indicator field for DNST and other threats
            domain_conditions.append(f'jsonPayload.threatInfo.threatIndicator="{domain}"')
            domain_conditions.append(f'jsonPayload.threatInfo.threatIndicator="{domain}."')
        
        return " OR ".join(domain_conditions) if domain_conditions else ""
    
    def _build_gcp_log_filter(self, domains: List[str], start_timestamp: str, end_timestamp: str) -> str:
        """Build complete GCP Cloud Logging filter"""
        log_filter = f'''resource.type="networksecurity.googleapis.com/DnsThreatDetector"
jsonPayload.dnsQuery.vmInstanceId="{self.vm_instance_id}"
timestamp>="{start_timestamp}"
timestamp<="{end_timestamp}"'''
        
        domain_filter = self._build_domain_filter(domains)
        if domain_filter:
            log_filter += f'\n({domain_filter})'
        
        return log_filter
    
    def _execute_gcloud_command(self, log_filter: str) -> Optional[List[Dict]]:
        """Execute gcloud logging command and return parsed results"""
        gcloud_command = [
            "gcloud", "logging", "read",
            log_filter,
            f"--project={self.project_id}",
            f"--limit={self.max_entries}",
            "--format=json"
        ]
        
        try:
            # Check if gcloud is available
            subprocess.run(["gcloud", "version"], capture_output=True, text=True, timeout=10, check=True)
            
            # Execute the gcloud command
            result = subprocess.run(
                gcloud_command,
                capture_output=True,
                text=True,
                timeout=120  # 2 minutes timeout
            )
            
            if result.returncode != 0:
                logger.error(f"❌ Error querying threat logs: {result.stderr}")
                return None
            
            if not result.stdout.strip():
                return []
            
            return json.loads(result.stdout)
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Error executing gcloud command: {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"❌ Error parsing JSON response: {e}")
            return None
        except FileNotFoundError:
            logger.error("❌ gcloud CLI not available for log querying")
            return None
        except Exception as e:
            logger.error(f"💥 Unexpected error querying threat logs: {e}")
            return None
    
    def _parse_threat_log_entries(self, raw_logs: List[Dict]) -> List[ThreatEvent]:
        """Parse raw GCP log entries into ThreatEvent objects"""
        threat_events = []
        
        for entry in raw_logs:
            try:
                # Extract threat detection information
                json_payload = entry.get('jsonPayload', {})
                dns_query = json_payload.get('dnsQuery', {})
                threat_info = json_payload.get('threatInfo', {})
                
                query_name = dns_query.get('queryName', '').rstrip('.')
                threat_id_found = threat_info.get('threatId', '')
                threat_feed = threat_info.get('threatFeed', '')
                
                if query_name:
                    threat_event = ThreatEvent(
                        timestamp=entry.get('timestamp', ''),
                        query_name=query_name,
                        threat_id=threat_id_found,
                        threat_feed=threat_feed,
                        vm_instance_id=dns_query.get('vmInstanceId', ''),
                        source_ip=dns_query.get('sourceIP', ''),
                        query_type=dns_query.get('queryType', ''),
                        response_code=dns_query.get('responseCode', ''),
                        raw_entry=entry
                    )
                    threat_events.append(threat_event)
            
            except Exception as e:
                logger.warning(f"Error processing threat log entry: {e}")
                continue
        
        return threat_events
    
    def _fetch_gcp_threat_logs(self, domains: List[str], category: str,
                              start_time: Optional[datetime] = None,
                              end_time: Optional[datetime] = None) -> List[ThreatEvent]:
        """
        Fetch real threat detection logs from GCP Cloud Logging
        
        Args:
            domains: List of domains to search for threats
            category: Category name for context
            start_time: Start time for log search
            end_time: End time for log search
            
        Returns:
            List of ThreatEvent objects from GCP logs
        """
        if not domains:
            return []
        
        # Calculate time range
        if start_time and end_time:
            start_timestamp = start_time.strftime(TIMESTAMP_FORMAT)
            end_timestamp = end_time.strftime(TIMESTAMP_FORMAT)
        else:
            end_time_calc = datetime.now(timezone.utc)
            start_time_calc = end_time_calc - timedelta(hours=self.hours_back)
            start_timestamp = start_time_calc.strftime(TIMESTAMP_FORMAT)
            end_timestamp = end_time_calc.strftime(TIMESTAMP_FORMAT)
        
        logger.info(f"🔍 Fetching GCP threat logs for {category}: {len(domains)} domains")
        logger.info(f"⏰ Time range: {start_timestamp} to {end_timestamp}")
        
        # Build GCP Cloud Logging filter
        log_filter = self._build_gcp_log_filter(domains, start_timestamp, end_timestamp)
        logger.debug(f"🔍 GCP log filter: {log_filter}")
        
        # Execute gcloud command
        raw_logs = self._execute_gcloud_command(log_filter)
        if raw_logs is None:
            return []
        
        if not raw_logs:
            logger.info(f"ℹ️ No threat logs found for {category}")
            return []
        
        logger.info(f"✅ Retrieved {len(raw_logs)} threat log entries for {category}")
        return self._parse_threat_log_entries(raw_logs)
    
    def _extract_unique_domains_from_threats(self, threat_events: List[ThreatEvent]) -> List[str]:
        """
        Extract unique domain names from threat events.
        For DNST tunneling, uses threatIndicator; for others uses query_name.
        
        Args:
            threat_events: List of ThreatEvent objects
            
        Returns:
            List of unique domain names from threats
        """
        unique_domains = set()
        
        for event in threat_events:
            try:
                # For DNST tunneling, use threatIndicator instead of query_name
                if 'DNST' in event.threat_id and event.raw_entry:
                    threat_info = event.raw_entry.get('jsonPayload', {}).get('threatInfo', {})
                    domain = threat_info.get('threatIndicator', '')
                else:
                    # For non-DNST threats, use query_name
                    domain = event.query_name
                
                if domain:
                    # Remove trailing dot and convert to lowercase for consistency
                    domain = domain.rstrip('.').lower()
                    # Skip empty domains and internal/system domains
                    if domain and not any(excluded in domain for excluded in ['internal', 'local', 'googleapis']):
                        unique_domains.add(domain)
                    
            except Exception as e:
                logger.warning(f"Error extracting domain from threat event: {e}")
                continue
        
        return sorted(unique_domains)
    
    def _fetch_category_threats(self, dig_result: CategoryDigResult,
                               start_time: Optional[datetime] = None,
                               end_time: Optional[datetime] = None) -> CategoryThreatResult:
        """
        Fetch threat events for a single category's successfully resolved domains
        
        Args:
            dig_result: CategoryDigResult with dig information
            start_time: Start time for threat log search
            end_time: End time for threat log search
            
        Returns:
            CategoryThreatResult with threat detection information
        """
        threat_result = CategoryThreatResult.from_category_dig_result(dig_result)
        
        if not dig_result.successful_domains:
            logger.info(f"📭 No successful domains to fetch threats for category: {dig_result.category}")
            threat_result.threat_summary = {
                'total_successful_domains': 0,
                'detected_domains_count': 0,
                'undetected_domains_count': 0,
                'detection_rate': 0.0,
                'threat_events_count': 0
            }
            return threat_result
        
        logger.info(f"🔍 Fetching threats for {dig_result.category}: {len(dig_result.successful_domains)} successful domains")
        
        # Fetch threat events based on mode
        if self.mode == "simulation":
            threat_events = self._generate_simulated_threat_events(
                dig_result.successful_domains, 
                dig_result.category
            )
        else:  # GCP mode
            threat_events = self._fetch_gcp_threat_logs(
                dig_result.successful_domains,
                dig_result.category,
                start_time,
                end_time
            )
        
        # Extract detected domains from threat events
        detected_domains_set = set()
        for event in threat_events:
            # Normalize domain for matching
            domain = event.query_name.rstrip('.').lower()
            detected_domains_set.add(domain)
        
        # Filter detected domains to only include successfully resolved ones
        successful_domains_lower = {d.lower() for d in dig_result.successful_domains}
        detected_domains = [d for d in detected_domains_set if d in successful_domains_lower]
        
        # Calculate undetected domains
        undetected_domains = [d for d in dig_result.successful_domains 
                             if d.lower() not in detected_domains_set]
        
        # Update threat result
        threat_result.threat_events = threat_events
        threat_result.detected_domains = detected_domains
        threat_result.undetected_domains = undetected_domains
        
        # Calculate summary statistics
        total_successful = len(dig_result.successful_domains)
        detected_count = len(detected_domains)
        undetected_count = len(undetected_domains)
        detection_rate = (detected_count / total_successful * 100) if total_successful > 0 else 0.0
        
        threat_result.threat_summary = {
            'total_successful_domains': total_successful,
            'detected_domains_count': detected_count,
            'undetected_domains_count': undetected_count,
            'detection_rate': detection_rate,
            'threat_events_count': len(threat_events)
        }
        
        logger.info(f"📊 {dig_result.category} threat detection: "
                   f"{detected_count}/{total_successful} detected ({detection_rate:.1f}%)")
        
        if undetected_count > 0:
            logger.info(f"⚠️ {dig_result.category}: {undetected_count} domains had no threat detection")
        
        return threat_result
    
    def fetch_threats_for_categories(self, dig_results: Dict[str, CategoryDigResult],
                                   start_time: Optional[datetime] = None,
                                   end_time: Optional[datetime] = None) -> Dict[str, CategoryThreatResult]:
        """
        Fetch threat events for multiple categories
        
        Args:
            dig_results: Dictionary of category name to CategoryDigResult objects
            start_time: Start time for threat log search  
            end_time: End time for threat log search
            
        Returns:
            Dictionary of category name to CategoryThreatResult objects
        """
        logger.info(f"🚀 Fetching threat events for {len(dig_results)} categories")
        
        results = {}
        
        for category, dig_result in dig_results.items():
            try:
                threat_result = self._fetch_category_threats(dig_result, start_time, end_time)
                results[category] = threat_result
                logger.info(f"✅ Completed threat fetching for {category}")
            except Exception as e:
                logger.error(f"❌ Error processing threats for category {category}: {e}")
                # Create empty result for failed category
                results[category] = CategoryThreatResult.from_category_dig_result(dig_result)
        
        # Log overall summary
        total_successful = sum(len(result.successful_domains) for result in results.values())
        total_detected = sum(len(result.detected_domains) for result in results.values())
        overall_detection_rate = (total_detected / total_successful * 100) if total_successful > 0 else 0.0
        
        logger.info(f"🎯 Overall threat detection summary: {total_detected}/{total_successful} "
                   f"detected ({overall_detection_rate:.1f}%)")
        
        return results

# Convenience functions
def fetch_threats_for_categories(dig_results: Dict[str, CategoryDigResult],
                               mode: str = "simulation",
                               project_id: Optional[str] = None,
                               vm_instance_id: Optional[str] = None,
                               vm_zone: Optional[str] = None,
                               hours_back: float = 2.0,
                               start_time: Optional[datetime] = None,
                               end_time: Optional[datetime] = None) -> Dict[str, CategoryThreatResult]:
    """
    Convenience function to fetch threat events for category dig results
    
    Args:
        dig_results: Dictionary of CategoryDigResult objects
        mode: "simulation" or "gcp"
        project_id: GCP project ID (required for GCP mode)
        vm_instance_id: VM instance ID (required for GCP mode)
        vm_zone: VM zone (required for GCP mode)
        hours_back: How many hours back to search
        start_time: Start time for threat log search
        end_time: End time for threat log search
        
    Returns:
        Dictionary of CategoryThreatResult objects
    """
    fetcher = ThreatEventFetcher(
        mode=mode,
        project_id=project_id,
        vm_instance_id=vm_instance_id,
        vm_zone=vm_zone,
        hours_back=hours_back
    )
    
    return fetcher.fetch_threats_for_categories(dig_results, start_time, end_time)

if __name__ == "__main__":
    # Example usage
    import logging
    from .sampler import ThreatDomainSampler
    from .digger import dig_domains_for_categories
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Sample and dig some domains
    sampler = ThreatDomainSampler()
    samples = sampler.sample_all_categories(5)
    dig_results = dig_domains_for_categories(samples)
    
    # Fetch threat events (simulation mode)
    fetcher = ThreatEventFetcher(mode="simulation")
    threat_results = fetcher.fetch_threats_for_categories(dig_results)
    
    # Print summary
    print("\n📊 Threat Detection Results Summary:")
    for category, result in threat_results.items():
        summary = result.threat_summary
        if summary.get('total_successful_domains', 0) > 0:
            print(f"  {category}: {summary['detected_domains_count']}/{summary['total_successful_domains']} "
                  f"detected ({summary['detection_rate']:.1f}%)")
