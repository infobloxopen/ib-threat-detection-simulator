"""
Threat Detection Simulator v2 - Threat Event Fetcher Module

This module handles fetching threat detection event logs for successfully resolved domains.
It takes CategoryDigResult objects from the digger and searches for threat detection events,
calculating detection rates and providing detailed threat analysis.

Key features:
- Local threat log simulation (file-based) for testing
- GCP Cloud Logging integration for real threat detection logs
- Automatic VM metadata detection for GCP mode
- Detection rate calculation based on successfully digged domains
- Detailed threat event analysis and filtering
- Extends CategoryDigResult with threat detection information
"""

import json
import logging
import subprocess
import tempfile
import time
import random
from dataclasses import dataclass, field
@dataclass
class FetcherConfig:
    batch_size: int = 25
    parallel_batches: bool = False
    max_parallel_workers: int = 3
    per_batch_timeout: int = 60
    retry_attempts: int = 3
    salvage_enabled: bool = False
    salvage_wait_seconds: int = 5
    streaming_mode: bool = False
    streaming_poll_interval: float = 2.0
    streaming_max_seconds: int = 60
    streaming_stability_rounds: int = 2

from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from .digger import CategoryDigResult
from .gcp_utils import auto_configure_threat_fetcher, GCPError

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
                 hours_back: float = 3.0,
                 max_entries: int = 5000,
                 auto_detect: bool = True,
                 fast_mode: bool = False,
                 config: Optional[FetcherConfig] = None):
        """
        Initialize the threat event fetcher
        
        Args:
            mode: "simulation" for local file-based testing, "gcp" for real GCP logs
            project_id: GCP project ID (auto-detected if None and auto_detect=True)
            vm_instance_id: VM instance ID (auto-detected if None and auto_detect=True)
            vm_zone: VM zone (auto-detected if None and auto_detect=True)
            hours_back: How many hours back to search for logs
            max_entries: Maximum number of log entries to retrieve
            auto_detect: Automatically detect VM metadata for GCP mode
        """
        self.mode = mode
        self.hours_back = hours_back
        self.max_entries = max_entries
        self.fast_mode = fast_mode
        cfg = config or FetcherConfig()
        self.batch_size = cfg.batch_size
        self.parallel_batches = cfg.parallel_batches
        self.max_parallel_workers = cfg.max_parallel_workers
        self.per_batch_timeout = cfg.per_batch_timeout
        self.retry_attempts = cfg.retry_attempts
        # internal state & health reporting
        self._validated_gcloud = False
        self.health_report = {
            'categories_skipped_due_to_error': [],
            'batches_failed': 0,
            'retries_used': 0,
            'per_category': {},
            'late_detection': {
                'salvage_enabled': cfg.salvage_enabled,
                'streaming_mode': cfg.streaming_mode,
                'categories_salvaged': {},
                'categories_streamed': {}
            }
        }
        # salvage / streaming config
        self.salvage_enabled = cfg.salvage_enabled
        self.salvage_wait_seconds = max(0, cfg.salvage_wait_seconds)
        self.streaming_mode = cfg.streaming_mode
        self.streaming_poll_interval = max(0.5, cfg.streaming_poll_interval)
        self.streaming_max_seconds = max(1, cfg.streaming_max_seconds)
        self.streaming_stability_rounds = max(1, cfg.streaming_stability_rounds)
        
        # Initialize VM metadata parameters
        self.project_id = project_id
        self.vm_instance_id = vm_instance_id
        self.vm_zone = vm_zone
        
        # Handle GCP mode configuration
        if mode == "gcp":
            self._configure_gcp_mode(auto_detect, project_id, vm_instance_id, vm_zone)
        
        logger.info(f"🎯 ThreatEventFetcher initialized in {mode} mode")
        
        if mode == "gcp":
            self._validate_gcp_parameters()
        else:
            logger.info("🧪 Using simulation mode with local threat event generation")
    
    def _configure_gcp_mode(self, auto_detect: bool, project_id: Optional[str], 
                           vm_instance_id: Optional[str], vm_zone: Optional[str]) -> None:
        """Configure GCP mode with automatic detection if needed"""
        if auto_detect and not all([project_id, vm_instance_id, vm_zone]):
            self._auto_detect_vm_metadata(project_id, vm_instance_id, vm_zone)
    
    def _auto_detect_vm_metadata(self, project_id: Optional[str], 
                                vm_instance_id: Optional[str], vm_zone: Optional[str]) -> None:
        """Auto-detect VM metadata for GCP mode"""
        logger.info("🔍 Auto-detecting VM metadata for GCP mode...")
        try:
            auto_project_id, auto_vm_instance_id, auto_vm_zone = auto_configure_threat_fetcher()
            
            # Use auto-detected values if not provided
            self.project_id = project_id or auto_project_id
            self.vm_instance_id = vm_instance_id or auto_vm_instance_id
            self.vm_zone = vm_zone or auto_vm_zone
            
            logger.info("✅ Auto-detected VM metadata:")
            logger.info(f"   Project: {self.project_id}")
            logger.info(f"   VM Instance: {self.vm_instance_id}")
            logger.info(f"   Zone: {self.vm_zone}")
            
        except GCPError as e:
            logger.warning(f"⚠️ Auto-detection failed: {e}")
            logger.info("💡 Falling back to provided parameters or manual configuration")
    
    def _validate_gcp_parameters(self) -> None:
        """Validate that all required GCP parameters are available"""
        if not all([self.project_id, self.vm_instance_id, self.vm_zone]):
            missing_params = []
            if not self.project_id:
                missing_params.append("project_id")
            if not self.vm_instance_id:
                missing_params.append("vm_instance_id")
            if not self.vm_zone:
                missing_params.append("vm_zone")
                
            raise ValueError(f"GCP mode requires: {', '.join(missing_params)}. "
                           f"Auto-detection failed and manual parameters are incomplete.")
        
        logger.info(f"🌐 GCP config: project={self.project_id}, vm={self.vm_instance_id}, zone={self.vm_zone}")
    
    def _generate_simulated_threat_events(self, domains: List[str], category: str) -> List[ThreatEvent]:
        """
        Generate simulated threat events for testing purposes with realistic detection rates
        
        Args:
            domains: List of domains to simulate threats for
            category: Category name for threat type mapping
            
        Returns:
            List of simulated ThreatEvent objects
        """
        import random
        
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
        
        # Realistic detection rates by category (based on threat intelligence effectiveness)
        detection_rates = {
            "Phishing": 0.75,           # High detection for known phishing
            "Lookalikes": 0.65,         # Medium-high for lookalike domains
            "TDS": 0.70,                # High for traffic direction systems
            "Command_&_Control": 0.80,  # Very high for C&C domains
            "DGAS_&_RDGAS": 0.60,       # Medium for legacy DGA category
            "Emerging_Domains": 0.45,   # Lower for new/emerging threats
            "High_Risk": 0.85,          # Very high for known high-risk
            "Malicious_Domains": 0.90,  # Very high for confirmed malicious
            "DGA_Malware": 0.75,        # High for DGA domains
            "DNST_Tunneling": 0.95      # Very high for DNS tunneling patterns
        }
        
        threat_id = threat_id_mapping.get(category, "Malicious_Generic")
        detection_rate = detection_rates.get(category, 0.50)  # Default 50% if unknown
        
        # Use randomization for realistic simulation
        random.seed(42)  # Fixed seed for reproducible testing
        detected_domains = []
        
        for domain in domains:
            # Each domain has individual chance based on category detection rate
            if random.random() < detection_rate:
                detected_domains.append(domain)
        
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
        
        actual_detection_rate = (len(threat_events) / len(domains) * 100) if domains else 0
        logger.info("🧪 Simulated %d threat events for %s (%.1f%% detection)", len(threat_events), category, actual_detection_rate)
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
        
        # Fast mode trims filter size: omit trailing dot + threatIndicator duplicates (except DNST for indicator)
        if self.fast_mode:
            fast_conditions = []
            for domain in domains:
                fast_conditions.append(f'jsonPayload.dnsQuery.queryName="{domain}"')
                # For DNST we still include threatIndicator once
                if 'dnst' in domain.lower():  # heuristic; domain itself may not reveal DNST, keep minimal
                    fast_conditions.append(f'jsonPayload.threatInfo.threatIndicator="{domain}"')
            return " OR ".join(fast_conditions) if fast_conditions else ""
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
    
    def _validate_gcloud_once(self) -> None:
        """Validate gcloud CLI availability once at initialization time."""
        if self._validated_gcloud or self.mode != 'gcp':
            return
        try:
            subprocess.run(["gcloud", "version"], capture_output=True, text=True, timeout=30, check=True)
            self._validated_gcloud = True
        except Exception as e:
            logger.error(f"❌ gcloud CLI validation failed: {e}")
            self._validated_gcloud = False

    def _execute_gcloud_command(self, log_filter: str) -> Optional[List[Dict]]:
        """Execute gcloud logging command with retries and return parsed results.

        Returns list (possibly empty) or None on definitive failure.
        Updates health_report retries_used counter.
        """
        self._validate_gcloud_once()
        gcloud_command = [
            "gcloud", "logging", "read",
            log_filter,
            f"--project={self.project_id}",
            f"--limit={self.max_entries}",
            "--format=json"
        ]
        attempts = 0
        backoff_base = 2
        while attempts < self.retry_attempts:
            attempts += 1
            try:
                result = subprocess.run(
                    gcloud_command,
                    capture_output=True,
                    text=True,
                    timeout=self.per_batch_timeout
                )
                if result.returncode != 0:
                    raise RuntimeError(result.stderr.strip() or 'non-zero exit')
                output = result.stdout.strip()
                if not output:
                    # No logs for this batch
                    self.health_report['retries_used'] += (attempts - 1)
                    return []
                try:
                    parsed = json.loads(output)
                except json.JSONDecodeError as je:
                    raise RuntimeError(f'JSON parse error: {je}')
                self.health_report['retries_used'] += (attempts - 1)
                return parsed
            except Exception as e:
                if attempts < self.retry_attempts:
                    sleep_time = (backoff_base ** (attempts - 1)) + random.uniform(0, 0.5)
                    logger.warning(f"⏳ Batch attempt {attempts} failed ({e}); retrying in {sleep_time:.1f}s ...")
                    time.sleep(sleep_time)
                    continue
                logger.error(f"💥 Exhausted retries querying threat logs: {e}")
                self.health_report['retries_used'] += (attempts - 1)
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
                              end_time: Optional[datetime] = None,
                              batch_size: Optional[int] = None) -> List[ThreatEvent]:
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
        
        def _calc_time_range() -> Tuple[str, str]:
            if start_time and end_time:
                return start_time.strftime(TIMESTAMP_FORMAT), end_time.strftime(TIMESTAMP_FORMAT)
            end_now = datetime.now(timezone.utc)
            start_now = end_now - timedelta(hours=self.hours_back)
            return start_now.strftime(TIMESTAMP_FORMAT), end_now.strftime(TIMESTAMP_FORMAT)
        start_timestamp, end_timestamp = _calc_time_range()
        
        logger.info(f"🔍 Fetching GCP threat logs for {category}: {len(domains)} domains")
        logger.info(f"⏰ Time range: {start_timestamp} to {end_timestamp}")
        
        # Batch domains to avoid excessively long OR filter strings
        # Ensure batch_size has a concrete int value
        batch_size = batch_size or self.batch_size or 25
        all_events: List[ThreatEvent] = []
        def _build_batches() -> List[Tuple[int, List[str]]]:
            return [
                (i // batch_size + 1, domains[i:i+batch_size])
                for i in range(0, len(domains), batch_size)
            ]
        batches = _build_batches()

        def process_batch(batch_info):
            """Process a single batch; extracted to reduce complexity."""
            idx, batch_domains = batch_info
            log_filter_local = self._build_gcp_log_filter(batch_domains, start_timestamp, end_timestamp)
            logger.debug(f"🔍 GCP log filter batch {idx}: {log_filter_local}")
            raw_logs_local = self._execute_gcloud_command(log_filter_local)
            if not raw_logs_local:
                if raw_logs_local is None:
                    self.health_report['batches_failed'] += 1
                return []
            return self._parse_threat_log_entries(raw_logs_local)

        if self.parallel_batches and len(batches) > 1:
            try:
                from concurrent.futures import ThreadPoolExecutor, as_completed
                with ThreadPoolExecutor(max_workers=self.max_parallel_workers) as executor:
                    futures = {executor.submit(process_batch, b): b[0] for b in batches}
                    for future in as_completed(futures):
                        try:
                            events = future.result()
                            all_events.extend(events)
                        except Exception as e:
                            logger.error(f"💥 Parallel batch processing error: {e}")
                            self.health_report['batches_failed'] += 1
            except Exception as e:
                logger.warning(f"⚠️ Falling back to sequential batch processing due to error enabling parallelism: {e}")
                for b in batches:
                    all_events.extend(process_batch(b))
        else:
            for b in batches:
                all_events.extend(process_batch(b))
        if not all_events:
            logger.info(f"ℹ️ No threat logs found for {category}")
            return []
        logger.info(f"✅ Retrieved {len(all_events)} threat log entries for {category} (batched)")
        return all_events
    
    def _extract_unique_domains_from_threats(self, threat_events: List[ThreatEvent]) -> List[str]:
        """
        Extract unique domain names from threat events.
        For DNST tunneling, uses threatIndicator; for others uses query_name.
        
        Args:
            threat_events: List of ThreatEvent objects
            
        Returns:
            List of unique domain names from threats
        """
        unique_domains: Set[str] = set()

        def _domain_from_event(ev: ThreatEvent) -> Optional[str]:
            try:
                if 'DNST' in ev.threat_id or 'TI-DNST' in ev.threat_id:
                    threat_info = ev.raw_entry.get('jsonPayload', {}).get('threatInfo', {}) if ev.raw_entry else {}
                    base = threat_info.get('threatIndicator', ev.query_name)
                else:
                    base = ev.query_name
                if not base:
                    return None
                base = base.rstrip('.').lower()
                if any(excluded in base for excluded in ['internal', 'local', 'googleapis']):
                    return None
                return base
            except Exception as e:
                logger.warning(f"Error extracting domain from threat event: {e}")
                return None

        for ev in threat_events:
            dom = _domain_from_event(ev)
            if dom:
                unique_domains.add(dom)
        return sorted(unique_domains)

    # ---- Category threat fetching refactor helpers ----
    def _prepare_domains_for_threat_search(self, dig_result: CategoryDigResult) -> Tuple[List[str], bool]:
        is_dnst = 'DNST' in dig_result.category.upper() or 'TUNNELING' in dig_result.category.upper()
        if is_dnst:
            unique_domains = list(set(dig_result.successful_domains))
            logger.info(f"🔗 DNST {dig_result.category}: Deduplicating {len(dig_result.successful_domains)} queries to {len(unique_domains)} unique domains")
            return unique_domains, True
        return dig_result.successful_domains, False

    def _initial_threat_fetch(self, domains: List[str], dig_result: CategoryDigResult,
                              start_time: Optional[datetime], end_time: Optional[datetime]) -> Tuple[List[ThreatEvent], bool, bool, datetime, datetime]:
        start_fetch = datetime.now(timezone.utc)
        query_failed = False
        no_logs_found = False
        if self.mode == 'simulation':
            events = self._generate_simulated_threat_events(domains, dig_result.category)
        else:
            events = self._fetch_gcp_threat_logs(domains, dig_result.category, start_time, end_time, batch_size=self.batch_size)
            if not events:
                query_failed = self.health_report['batches_failed'] > 0
                no_logs_found = not query_failed
        end_fetch = datetime.now(timezone.utc)
        return events, query_failed, no_logs_found, start_fetch, end_fetch

    def _run_salvage(self, threat_events: List[ThreatEvent], domains_for_search: List[str], dig_result: CategoryDigResult,
                     start_time: Optional[datetime]) -> List[ThreatEvent]:
        if self.mode != 'gcp' or not self.salvage_enabled:
            return threat_events
        initially_detected = {ev.query_name.rstrip('.').lower() for ev in threat_events}
        undetected = [d for d in domains_for_search if d.lower() not in initially_detected]
        if not undetected:
            return threat_events
        logger.info(f"🛟 Salvage phase for {dig_result.category}: waiting {self.salvage_wait_seconds}s for late ingestion ({len(undetected)} domains)")
        time.sleep(self.salvage_wait_seconds)
        salvage_events = self._fetch_gcp_threat_logs(undetected, dig_result.category, start_time, datetime.now(timezone.utc))
        if not salvage_events:
            logger.info(f"🛟 Salvage found no additional events for {dig_result.category}")
            return threat_events
        existing_ids = {ev.raw_entry.get('insertId') for ev in threat_events if ev.raw_entry}
        new_events = [ev for ev in salvage_events if ev.raw_entry and ev.raw_entry.get('insertId') not in existing_ids]
        threat_events.extend(new_events)
        self.health_report['late_detection']['categories_salvaged'][dig_result.category] = {
            'added_events': len(new_events),
            'late_domains_detected': list({ev.query_name.rstrip('.') for ev in new_events})
        }
        logger.info(f"🛟 Salvage added {len(new_events)} events for {dig_result.category}")
        return threat_events

    def _run_streaming(self, threat_events: List[ThreatEvent], domains_for_search: List[str], dig_result: CategoryDigResult,
                       start_time: Optional[datetime]) -> List[ThreatEvent]:
        if self.mode != 'gcp' or not self.streaming_mode:
            return threat_events
        streaming_start = time.time()
        stability_counter = 0
        last_detect_count = len({ev.query_name for ev in threat_events})
        while (time.time() - streaming_start) < self.streaming_max_seconds:
            detected_names = {ev.query_name.rstrip('.').lower() for ev in threat_events}
            remaining = [d for d in domains_for_search if d.lower() not in detected_names]
            if not remaining:
                logger.info(f"📡 Streaming phase complete for {dig_result.category}: all domains detected")
                break
            logger.debug(f"📡 Streaming poll for {dig_result.category}: {len(remaining)} remaining; sleeping {self.streaming_poll_interval}s")
            time.sleep(self.streaming_poll_interval)
            poll_events = self._fetch_gcp_threat_logs(remaining, dig_result.category, start_time, datetime.now(timezone.utc))
            if poll_events:
                existing_ids = {ev.raw_entry.get('insertId') for ev in threat_events if ev.raw_entry}
                new_events = [ev for ev in poll_events if ev.raw_entry and ev.raw_entry.get('insertId') not in existing_ids]
                if new_events:
                    threat_events.extend(new_events)
                    logger.info(f"📡 Streaming added {len(new_events)} events for {dig_result.category}")
            current_detect_count = len({ev.query_name for ev in threat_events})
            if current_detect_count == last_detect_count:
                stability_counter += 1
            else:
                stability_counter = 0
                last_detect_count = current_detect_count
            if stability_counter >= self.streaming_stability_rounds:
                logger.info(f"📡 Streaming stability reached for {dig_result.category} (no new detections in {stability_counter} polls)")
                break
        self.health_report['late_detection']['categories_streamed'][dig_result.category] = {
            'final_detected_count': len({ev.query_name for ev in threat_events}),
            'duration_seconds': round(time.time() - streaming_start, 2)
        }
        return threat_events

    def _compute_detection_metrics(self, dig_result: CategoryDigResult, threat_events: List[ThreatEvent], is_dnst: bool) -> Tuple[List[str], List[str], int, int, float]:
        detected_set: Set[str] = set()
        for ev in threat_events:
            if is_dnst and ev.raw_entry:
                threat_info = ev.raw_entry.get('jsonPayload', {}).get('threatInfo', {})
                dom = threat_info.get('threatIndicator', ev.query_name)
            else:
                dom = ev.query_name
            detected_set.add(dom.rstrip('.').lower())
        if is_dnst:
            unique_queried = {d.lower() for d in dig_result.successful_domains}
            detected = [d for d in detected_set if d in unique_queried]
            undetected = [d for d in unique_queried if d not in detected_set]
            total_unique = len(unique_queried)
            det_count = len(detected)
            undet_count = len(undetected)
            rate = (det_count / total_unique * 100) if total_unique else 0.0
            logger.info("🔗 DNST Detection Logic for %s: %d threats detected from %d unique domain(s) tested -> %.1f%% detection rate", dig_result.category, det_count, total_unique, rate)
        else:
            successful_lower = {d.lower() for d in dig_result.successful_domains}
            detected = [d for d in detected_set if d in successful_lower]
            undetected = [d for d in dig_result.successful_domains if d.lower() not in detected_set]
            total_successful = len(dig_result.successful_domains)
            det_count = len(detected)
            undet_count = len(undetected)
            rate = (det_count / total_successful * 100) if total_successful else 0.0
        return detected, undetected, det_count, undet_count, rate
    
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
                'threat_events_count': 0,
                'fetch_duration_seconds': 0.0,
                'no_logs_found': True,
                'query_failed': False
            }
            return threat_result
        
        domains_for_threat_search, is_dnst = self._prepare_domains_for_threat_search(dig_result)
        logger.info(f"🔍 Fetching threats for {dig_result.category}: {len(domains_for_threat_search)} domains to search")

        threat_events, query_failed, no_logs_found, start_fetch, end_fetch = self._initial_threat_fetch(
            domains_for_threat_search, dig_result, start_time, end_time
        )
        if not query_failed:
            threat_events = self._run_salvage(threat_events, domains_for_threat_search, dig_result, start_time)
            threat_events = self._run_streaming(threat_events, domains_for_threat_search, dig_result, start_time)

        # Compute domain-level detection metrics (distinct threat domains and legacy rate)
        detected_domains, undetected_domains, detected_count, undetected_count, _legacy_rate = self._compute_detection_metrics(
            dig_result, threat_events, is_dnst
        )
        successful_unique = len(set(dig_result.successful_domains))
        detection_rate = (detected_count / successful_unique * 100) if successful_unique else 0.0
        previous_events_domain_rate = (len(threat_events) / len(dig_result.successful_domains) * 100) if dig_result.successful_domains else 0.0
        
        # Update threat result
        threat_result.threat_events = threat_events
        threat_result.detected_domains = detected_domains
        threat_result.undetected_domains = undetected_domains
        # Populate dns_logs with raw entries (lightweight extraction) for advanced output enrichment
        dns_logs = []
        for ev in threat_events:
            dns_logs.append({
                "timestamp": ev.timestamp,
                "query_name": ev.query_name,
                "threat_id": ev.threat_id,
                "threat_feed": ev.threat_feed
            })
        setattr(threat_result, 'dns_logs', dns_logs)
        
        # Calculate summary statistics
        threat_result.threat_summary = {
            'total_successful_domains': len(dig_result.successful_domains),
            'detected_domains_count': detected_count,  # distinct threat domains detected
            'undetected_domains_count': undetected_count,
            'detection_rate': detection_rate,  # threat domains / dns domains * 100
            'detection_rate_previous_events_per_domain': previous_events_domain_rate,
            'detection_rate_legacy_domain_basis': _legacy_rate,
            'threat_events_count': len(threat_events),
            'fetch_duration_seconds': (end_fetch - start_fetch).total_seconds(),
            'no_logs_found': no_logs_found,
            'query_failed': query_failed,
            'late_salvage_added': self.health_report['late_detection']['categories_salvaged'].get(dig_result.category, {}).get('added_events', 0),
            'streaming_final_detected': self.health_report['late_detection']['categories_streamed'].get(dig_result.category, {}).get('final_detected_count', detected_count)
        }

        logger.info(
            "📊 %s threat detection: %d events; %d/%d distinct threat domains -> %.1f%% threat rate (prev events/domain: %.1f%%, legacy domain rate: %.1f%%)",
            dig_result.category,
            len(threat_events),
            detected_count,
            successful_unique,
            detection_rate,
            previous_events_domain_rate,
            _legacy_rate
        )
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
                self.health_report['categories_skipped_due_to_error'].append(category)
        
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
                               hours_back: float = 3.0,
                               start_time: Optional[datetime] = None,
                               end_time: Optional[datetime] = None,
                               auto_detect: bool = True,
                               fast_mode: bool = False) -> Dict[str, CategoryThreatResult]:
    """
    Convenience function to fetch threat events for category dig results
    
    Args:
        dig_results: Dictionary of CategoryDigResult objects
        mode: "simulation" or "gcp"
        project_id: GCP project ID (auto-detected if None and auto_detect=True)
        vm_instance_id: VM instance ID (auto-detected if None and auto_detect=True)
        vm_zone: VM zone (auto-detected if None and auto_detect=True)
        hours_back: How many hours back to search
        start_time: Start time for threat log search
        end_time: End time for threat log search
        auto_detect: Automatically detect VM metadata for GCP mode
        
    Returns:
        Dictionary of CategoryThreatResult objects
    """
    fetcher = ThreatEventFetcher(
        mode=mode,
        project_id=project_id,
        vm_instance_id=vm_instance_id,
        vm_zone=vm_zone,
        hours_back=hours_back,
        auto_detect=auto_detect,
        fast_mode=fast_mode
    )
    results = fetcher.fetch_threats_for_categories(dig_results, start_time, end_time)
    # Attach health_report for callers using wrapper (non-breaking: add attribute to function)
    setattr(results, 'health_report', fetcher.health_report)  # type: ignore
    return results

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
