"""
Unit tests for threat_detection_simulator.utils.threat_fetcher module (directory renamed from threat_detection_simulatorv2)

Tests the ThreatEventFetcher class and related functionality for fetching
threat detection events and calculating detection rates.
"""

import json
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, Mock, MagicMock
from typing import Dict, List

from threat_detection_simulator.utils.threat_fetcher import (
    ThreatEvent,
    CategoryThreatResult,
    ThreatEventFetcher,
    fetch_threats_for_categories
)
from threat_detection_simulator.utils.digger import CategoryDigResult, DigResult


class TestThreatEvent(unittest.TestCase):
    """Test ThreatEvent dataclass"""
    
    def test_threat_event_creation(self):
        """Test ThreatEvent object creation"""
        event = ThreatEvent(
            timestamp="2024-01-15T10:30:00Z",
            query_name="malicious.example.com",
            threat_id="Phishing",
            threat_feed="BloxOne_Threat_Feed",
            vm_instance_id="test-vm",
            source_ip="10.0.0.100",
            query_type="A",
            response_code="NOERROR"
        )
        
        self.assertEqual(event.timestamp, "2024-01-15T10:30:00Z")
        self.assertEqual(event.query_name, "malicious.example.com")
        self.assertEqual(event.threat_id, "Phishing")
        self.assertEqual(event.threat_feed, "BloxOne_Threat_Feed")
        self.assertEqual(event.vm_instance_id, "test-vm")
        self.assertEqual(event.source_ip, "10.0.0.100")
        self.assertEqual(event.query_type, "A")
        self.assertEqual(event.response_code, "NOERROR")
        self.assertEqual(event.raw_entry, {})


class TestCategoryThreatResult(unittest.TestCase):
    """Test CategoryThreatResult dataclass"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create a sample CategoryDigResult
        self.sample_dig_result = CategoryDigResult(
            category="Phishing",
            domains=["test1.com", "test2.com", "test3.com"],
            sampled_count=3,
            sampled_at="2024-01-15T10:00:00Z",
            successful_domains=["test1.com", "test2.com"],
            failed_domains=[
                {"domain": "test3.com", "error": "NXDOMAIN", "details": "Name does not exist"}
            ],
            dig_results={
                "test1.com": DigResult(
                    domain="test1.com", 
                    status="success", 
                    output="1.2.3.4",
                    error="",
                    dns_server="8.8.8.8",
                    command="dig @8.8.8.8 test1.com A +short",
                    execution_time=0.1,
                    timestamp="2024-01-15T10:00:00Z"
                ),
                "test2.com": DigResult(
                    domain="test2.com", 
                    status="success", 
                    output="5.6.7.8",
                    error="",
                    dns_server="8.8.8.8",
                    command="dig @8.8.8.8 test2.com A +short",
                    execution_time=0.2,
                    timestamp="2024-01-15T10:00:01Z"
                ),
                "test3.com": DigResult(
                    domain="test3.com", 
                    status="error", 
                    output="",
                    error="NXDOMAIN",
                    dns_server="8.8.8.8",
                    command="dig @8.8.8.8 test3.com A +short",
                    execution_time=0.05,
                    timestamp="2024-01-15T10:00:02Z"
                )
            },
            dig_summary={"total": 3, "successful": 2, "failed": 1, "success_rate": 66.7}
        )
    
    def test_from_category_dig_result(self):
        """Test creating CategoryThreatResult from CategoryDigResult"""
        threat_result = CategoryThreatResult.from_category_dig_result(self.sample_dig_result)
        
        # Check inherited fields
        self.assertEqual(threat_result.category, "Phishing")
        self.assertEqual(threat_result.domains, ["test1.com", "test2.com", "test3.com"])
        self.assertEqual(threat_result.sampled_count, 3)
        self.assertEqual(threat_result.sampled_at, "2024-01-15T10:00:00Z")
        self.assertEqual(threat_result.successful_domains, ["test1.com", "test2.com"])
        self.assertEqual(len(threat_result.failed_domains), 1)
        self.assertEqual(threat_result.dig_summary["successful"], 2)
        
        # Check new threat fields are empty initially
        self.assertEqual(threat_result.threat_events, [])
        self.assertEqual(threat_result.detected_domains, [])
        self.assertEqual(threat_result.undetected_domains, [])
        self.assertEqual(threat_result.threat_summary, {})
    
    def test_to_dict(self):
        """Test converting CategoryThreatResult to dictionary"""
        threat_result = CategoryThreatResult.from_category_dig_result(self.sample_dig_result)
        
        # Add some threat data
        threat_event = ThreatEvent(
            timestamp="2024-01-15T10:30:00Z",
            query_name="test1.com",
            threat_id="Phishing",
            threat_feed="BloxOne_Threat_Feed",
            vm_instance_id="test-vm",
            source_ip="10.0.0.100",
            query_type="A",
            response_code="NOERROR"
        )
        threat_result.threat_events = [threat_event]
        threat_result.detected_domains = ["test1.com"]
        threat_result.undetected_domains = ["test2.com"]
        threat_result.threat_summary = {"detection_rate": 50.0}
        
        result_dict = threat_result.to_dict()
        
        # Check basic fields
        self.assertEqual(result_dict["category"], "Phishing")
        self.assertEqual(result_dict["sampled_count"], 3)
        self.assertEqual(result_dict["detected_domains"], ["test1.com"])
        self.assertEqual(result_dict["undetected_domains"], ["test2.com"])
        self.assertEqual(result_dict["threat_summary"]["detection_rate"], 50.0)
        
        # Check threat events are converted to dicts
        self.assertEqual(len(result_dict["threat_events"]), 1)
        self.assertEqual(result_dict["threat_events"][0]["query_name"], "test1.com")


class TestThreatEventFetcher(unittest.TestCase):
    """Test ThreatEventFetcher class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.sample_dig_result = CategoryDigResult(
            category="Phishing",
            domains=["test1.com", "test2.com", "test3.com"],
            sampled_count=3,
            sampled_at="2024-01-15T10:00:00Z",
            successful_domains=["test1.com", "test2.com"],
            failed_domains=[
                {"domain": "test3.com", "error": "NXDOMAIN", "details": "Name does not exist"}
            ],
            dig_results={
                "test1.com": DigResult(
                    domain="test1.com", 
                    status="success", 
                    output="1.2.3.4",
                    error="",
                    dns_server="8.8.8.8",
                    command="dig @8.8.8.8 test1.com A +short",
                    execution_time=0.1,
                    timestamp="2024-01-15T10:00:00Z"
                ),
                "test2.com": DigResult(
                    domain="test2.com", 
                    status="success", 
                    output="5.6.7.8",
                    error="",
                    dns_server="8.8.8.8",
                    command="dig @8.8.8.8 test2.com A +short",
                    execution_time=0.2,
                    timestamp="2024-01-15T10:00:01Z"
                ),
                "test3.com": DigResult(
                    domain="test3.com", 
                    status="error", 
                    output="",
                    error="NXDOMAIN",
                    dns_server="8.8.8.8",
                    command="dig @8.8.8.8 test3.com A +short",
                    execution_time=0.05,
                    timestamp="2024-01-15T10:00:02Z"
                )
            },
            dig_summary={"total": 3, "successful": 2, "failed": 1, "success_rate": 66.7}
        )
    
    def test_init_simulation_mode(self):
        """Test ThreatEventFetcher initialization in simulation mode"""
        fetcher = ThreatEventFetcher(mode="simulation")
        
        self.assertEqual(fetcher.mode, "simulation")
        self.assertEqual(fetcher.hours_back, 2.0)
        self.assertEqual(fetcher.max_entries, 5000)
        self.assertIsNone(fetcher.project_id)
        self.assertIsNone(fetcher.vm_instance_id)
        self.assertIsNone(fetcher.vm_zone)
    
    def test_init_gcp_mode_valid(self):
        """Test ThreatEventFetcher initialization in GCP mode with valid parameters"""
        fetcher = ThreatEventFetcher(
            mode="gcp",
            project_id="test-project",
            vm_instance_id="test-vm",
            vm_zone="us-central1-a"
        )
        
        self.assertEqual(fetcher.mode, "gcp")
        self.assertEqual(fetcher.project_id, "test-project")
        self.assertEqual(fetcher.vm_instance_id, "test-vm")
        self.assertEqual(fetcher.vm_zone, "us-central1-a")
    
    def test_init_gcp_mode_missing_params(self):
        """Test ThreatEventFetcher initialization in GCP mode with missing parameters"""
        with self.assertRaises(ValueError) as context:
            ThreatEventFetcher(mode="gcp", project_id="test-project")  # Missing vm_instance_id and vm_zone
        
        self.assertIn("GCP mode requires", str(context.exception))
    
    def test_generate_simulated_threat_events(self):
        """Test simulated threat event generation"""
        fetcher = ThreatEventFetcher(mode="simulation", vm_instance_id="test-vm")
        domains = ["test1.com", "test2.com", "test3.com"]
        
        threat_events = fetcher._generate_simulated_threat_events(domains, "Phishing")
        
        # Should generate events for most domains (85% detection rate)
        self.assertGreater(len(threat_events), 0)
        self.assertLessEqual(len(threat_events), len(domains))
        
        # Check threat event structure
        for event in threat_events:
            self.assertIsInstance(event, ThreatEvent)
            self.assertIn(event.query_name, domains)
            self.assertEqual(event.threat_id, "Phishing")
            self.assertEqual(event.threat_feed, "BloxOne_Threat_Feed")
            self.assertEqual(event.vm_instance_id, "test-vm")
    
    def test_threat_id_mapping(self):
        """Test threat ID mapping for different categories"""
        fetcher = ThreatEventFetcher(mode="simulation")
        
        test_cases = [
            ("Phishing", "Phishing"),
            ("Command_&_Control", "Command_Control"),
            ("DGA_Malware", "DGA_Generic"),
            ("DNST_Tunneling", "TI-DNST"),
            ("Unknown_Category", "Malicious_Generic")
        ]
        
        for category, expected_threat_id in test_cases:
            events = fetcher._generate_simulated_threat_events(["test.com"], category)
            if events:  # Some categories might have 0 events due to randomness
                self.assertEqual(events[0].threat_id, expected_threat_id)
    
    def test_build_domain_filter(self):
        """Test domain filter building for GCP queries"""
        fetcher = ThreatEventFetcher(mode="gcp", project_id="test", vm_instance_id="test", vm_zone="test")
        domains = ["test1.com", "test2.com"]
        
        domain_filter = fetcher._build_domain_filter(domains)
        
        # Should include both query name and threat indicator filters
        self.assertIn('jsonPayload.dnsQuery.queryName="test1.com"', domain_filter)
        self.assertIn('jsonPayload.dnsQuery.queryName="test1.com."', domain_filter)
        self.assertIn('jsonPayload.threatInfo.threatIndicator="test1.com"', domain_filter)
        self.assertIn('jsonPayload.threatInfo.threatIndicator="test1.com."', domain_filter)
        self.assertIn(" OR ", domain_filter)
    
    def test_build_gcp_log_filter(self):
        """Test complete GCP log filter building"""
        fetcher = ThreatEventFetcher(mode="gcp", project_id="test", vm_instance_id="test-vm", vm_zone="test")
        domains = ["test.com"]
        start_time = "2024-01-15T10:00:00Z"
        end_time = "2024-01-15T12:00:00Z"
        
        log_filter = fetcher._build_gcp_log_filter(domains, start_time, end_time)
        
        # Check filter components
        self.assertIn('resource.type="networksecurity.googleapis.com/DnsThreatDetector"', log_filter)
        self.assertIn('jsonPayload.dnsQuery.vmInstanceId="test-vm"', log_filter)
        self.assertIn(f'timestamp>="{start_time}"', log_filter)
        self.assertIn(f'timestamp<="{end_time}"', log_filter)
        self.assertIn('jsonPayload.dnsQuery.queryName="test.com"', log_filter)
    
    @patch('subprocess.run')
    def test_execute_gcloud_command_success(self, mock_subprocess):
        """Test successful gcloud command execution"""
        fetcher = ThreatEventFetcher(mode="gcp", project_id="test", vm_instance_id="test", vm_zone="test")
        
        # Mock successful gcloud version check
        mock_subprocess.side_effect = [
            Mock(returncode=0),  # gcloud version check
            Mock(returncode=0, stdout='[{"test": "data"}]')  # gcloud logging read
        ]
        
        result = fetcher._execute_gcloud_command("test filter")
        
        self.assertEqual(result, [{"test": "data"}])
        self.assertEqual(mock_subprocess.call_count, 2)
    
    @patch('subprocess.run')
    def test_execute_gcloud_command_no_results(self, mock_subprocess):
        """Test gcloud command with no results"""
        fetcher = ThreatEventFetcher(mode="gcp", project_id="test", vm_instance_id="test", vm_zone="test")
        
        # Mock successful gcloud version check but empty results
        mock_subprocess.side_effect = [
            Mock(returncode=0),  # gcloud version check
            Mock(returncode=0, stdout='')  # gcloud logging read - empty
        ]
        
        result = fetcher._execute_gcloud_command("test filter")
        
        self.assertEqual(result, [])
    
    @patch('subprocess.run')
    def test_execute_gcloud_command_error(self, mock_subprocess):
        """Test gcloud command execution error"""
        fetcher = ThreatEventFetcher(mode="gcp", project_id="test", vm_instance_id="test", vm_zone="test")
        
        # Mock successful version check but failed logging command
        mock_subprocess.side_effect = [
            Mock(returncode=0),  # gcloud version check
            Mock(returncode=1, stderr="Permission denied")  # gcloud logging read error
        ]
        
        result = fetcher._execute_gcloud_command("test filter")
        
        self.assertIsNone(result)
    
    def test_parse_threat_log_entries(self):
        """Test parsing raw GCP log entries into ThreatEvent objects"""
        fetcher = ThreatEventFetcher(mode="gcp", project_id="test", vm_instance_id="test", vm_zone="test")
        
        raw_logs = [
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "jsonPayload": {
                    "dnsQuery": {
                        "queryName": "malicious.com.",
                        "vmInstanceId": "test-vm",
                        "sourceIP": "10.0.0.100",
                        "queryType": "A",
                        "responseCode": "NOERROR"
                    },
                    "threatInfo": {
                        "threatId": "Phishing",
                        "threatFeed": "BloxOne_Threat_Feed"
                    }
                }
            },
            {
                "timestamp": "2024-01-15T10:31:00Z",
                "jsonPayload": {
                    "dnsQuery": {
                        "queryName": "another-threat.com",
                        "vmInstanceId": "test-vm",
                        "sourceIP": "10.0.0.101",
                        "queryType": "A",
                        "responseCode": "NOERROR"
                    },
                    "threatInfo": {
                        "threatId": "Malicious_Generic",
                        "threatFeed": "BloxOne_Threat_Feed"
                    }
                }
            }
        ]
        
        threat_events = fetcher._parse_threat_log_entries(raw_logs)
        
        self.assertEqual(len(threat_events), 2)
        
        # Check first event
        event1 = threat_events[0]
        self.assertEqual(event1.timestamp, "2024-01-15T10:30:00Z")
        self.assertEqual(event1.query_name, "malicious.com")  # Trailing dot removed
        self.assertEqual(event1.threat_id, "Phishing")
        self.assertEqual(event1.threat_feed, "BloxOne_Threat_Feed")
        self.assertEqual(event1.vm_instance_id, "test-vm")
        self.assertEqual(event1.source_ip, "10.0.0.100")
        
        # Check second event
        event2 = threat_events[1]
        self.assertEqual(event2.query_name, "another-threat.com")
        self.assertEqual(event2.threat_id, "Malicious_Generic")
    
    def test_parse_threat_log_entries_malformed(self):
        """Test parsing malformed log entries"""
        fetcher = ThreatEventFetcher(mode="gcp", project_id="test", vm_instance_id="test", vm_zone="test")
        
        raw_logs = [
            {"invalid": "entry"},  # Missing required fields
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "jsonPayload": {
                    "dnsQuery": {
                        "queryName": "valid.com",
                        "vmInstanceId": "test-vm"
                    },
                    "threatInfo": {
                        "threatId": "Phishing"
                    }
                }
            }
        ]
        
        threat_events = fetcher._parse_threat_log_entries(raw_logs)
        
        # Should only parse the valid entry
        self.assertEqual(len(threat_events), 1)
        self.assertEqual(threat_events[0].query_name, "valid.com")
    
    def test_extract_unique_domains_from_threats(self):
        """Test extracting unique domains from threat events"""
        fetcher = ThreatEventFetcher(mode="simulation")
        
        threat_events = [
            ThreatEvent(
                timestamp="2024-01-15T10:30:00Z",
                query_name="test1.com",
                threat_id="Phishing",
                threat_feed="BloxOne_Threat_Feed",
                vm_instance_id="test-vm",
                source_ip="10.0.0.100",
                query_type="A",
                response_code="NOERROR"
            ),
            ThreatEvent(
                timestamp="2024-01-15T10:31:00Z",
                query_name="TEST1.COM",  # Duplicate with different case
                threat_id="Phishing",
                threat_feed="BloxOne_Threat_Feed",
                vm_instance_id="test-vm",
                source_ip="10.0.0.100",
                query_type="A",
                response_code="NOERROR"
            ),
            ThreatEvent(
                timestamp="2024-01-15T10:32:00Z",
                query_name="test2.com",
                threat_id="TI-DNST",
                threat_feed="BloxOne_Threat_Feed",
                vm_instance_id="test-vm",
                source_ip="10.0.0.100",
                query_type="A",
                response_code="NOERROR",
                raw_entry={
                    "jsonPayload": {
                        "threatInfo": {
                            "threatIndicator": "dnst-tunnel.com"
                        }
                    }
                }
            )
        ]
        
        unique_domains = fetcher._extract_unique_domains_from_threats(threat_events)
        
        # Should have 2 unique domains (test1.com and dnst-tunnel.com)
        # test1.com appears twice but different case, should be deduplicated
        # DNST threat should use threatIndicator instead of query_name
        self.assertEqual(len(unique_domains), 2)
        self.assertIn("test1.com", unique_domains)
        self.assertIn("dnst-tunnel.com", unique_domains)
    
    def test_fetch_category_threats_simulation(self):
        """Test fetching threats for a category in simulation mode"""
        fetcher = ThreatEventFetcher(mode="simulation", vm_instance_id="test-vm")
        
        result = fetcher._fetch_category_threats(self.sample_dig_result)
        
        # Check result structure
        self.assertIsInstance(result, CategoryThreatResult)
        self.assertEqual(result.category, "Phishing")
        self.assertEqual(result.successful_domains, ["test1.com", "test2.com"])
        
        # Check threat summary
        summary = result.threat_summary
        self.assertEqual(summary["total_successful_domains"], 2)
        self.assertGreaterEqual(summary["detected_domains_count"], 0)
        self.assertLessEqual(summary["detected_domains_count"], 2)
        self.assertEqual(summary["detected_domains_count"] + summary["undetected_domains_count"], 2)
        self.assertIsInstance(summary["detection_rate"], float)
        self.assertGreaterEqual(summary["detection_rate"], 0.0)
        self.assertLessEqual(summary["detection_rate"], 100.0)
    
    def test_fetch_category_threats_no_successful_domains(self):
        """Test fetching threats when no domains were successfully resolved"""
        fetcher = ThreatEventFetcher(mode="simulation")
        
        # Create dig result with no successful domains
        empty_dig_result = CategoryDigResult(
            category="Empty",
            domains=["failed1.com", "failed2.com"],
            sampled_count=2,
            sampled_at="2024-01-15T10:00:00Z",
            successful_domains=[],  # No successful domains
            failed_domains=[
                {"domain": "failed1.com", "error": "NXDOMAIN"},
                {"domain": "failed2.com", "error": "NXDOMAIN"}
            ],
            dig_results={},
            dig_summary={"total": 2, "successful": 0, "failed": 2, "success_rate": 0.0}
        )
        
        result = fetcher._fetch_category_threats(empty_dig_result)
        
        # Should have empty threat results
        self.assertEqual(len(result.threat_events), 0)
        self.assertEqual(len(result.detected_domains), 0)
        self.assertEqual(len(result.undetected_domains), 0)
        self.assertEqual(result.threat_summary["total_successful_domains"], 0)
        self.assertEqual(result.threat_summary["detection_rate"], 0.0)
    
    def test_fetch_threats_for_categories(self):
        """Test fetching threats for multiple categories"""
        fetcher = ThreatEventFetcher(mode="simulation", vm_instance_id="test-vm")
        
        # Create multiple dig results
        dig_results = {
            "Phishing": self.sample_dig_result,
            "Malware": CategoryDigResult(
                category="Malware",
                domains=["malware1.com", "malware2.com"],
                sampled_count=2,
                sampled_at="2024-01-15T10:00:00Z",
                successful_domains=["malware1.com"],
                failed_domains=[{"domain": "malware2.com", "error": "NXDOMAIN"}],
                dig_results={
                    "malware1.com": DigResult(
                        domain="malware1.com", 
                        status="success", 
                        output="9.8.7.6",
                        error="",
                        dns_server="8.8.8.8",
                        command="dig @8.8.8.8 malware1.com A +short",
                        execution_time=0.1,
                        timestamp="2024-01-15T10:00:00Z"
                    )
                },
                dig_summary={"total": 2, "successful": 1, "failed": 1, "success_rate": 50.0}
            )
        }
        
        results = fetcher.fetch_threats_for_categories(dig_results)
        
        # Check results structure
        self.assertEqual(len(results), 2)
        self.assertIn("Phishing", results)
        self.assertIn("Malware", results)
        
        # Check each result is CategoryThreatResult
        for category, result in results.items():
            self.assertIsInstance(result, CategoryThreatResult)
            self.assertEqual(result.category, category)
            self.assertIn("total_successful_domains", result.threat_summary)
            self.assertIn("detection_rate", result.threat_summary)


class TestConvenienceFunctions(unittest.TestCase):
    """Test convenience functions"""
    
    def test_fetch_threats_for_categories_convenience(self):
        """Test the convenience function for fetching threats"""
        # Create a simple dig result
        dig_result = CategoryDigResult(
            category="Test",
            domains=["test.com"],
            sampled_count=1,
            sampled_at="2024-01-15T10:00:00Z",
            successful_domains=["test.com"],
            failed_domains=[],
            dig_results={
                "test.com": DigResult(
                    domain="test.com", 
                    status="success", 
                    output="1.2.3.4",
                    error="",
                    dns_server="8.8.8.8",
                    command="dig @8.8.8.8 test.com A +short",
                    execution_time=0.1,
                    timestamp="2024-01-15T10:00:00Z"
                )
            },
            dig_summary={"total": 1, "successful": 1, "failed": 0, "success_rate": 100.0}
        )
        
        dig_results = {"Test": dig_result}
        
        # Test simulation mode
        results = fetch_threats_for_categories(
            dig_results,
            mode="simulation"
        )
        
        self.assertEqual(len(results), 1)
        self.assertIn("Test", results)
        self.assertIsInstance(results["Test"], CategoryThreatResult)


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete threat fetching workflow"""
    
    def test_complete_workflow_simulation(self):
        """Test complete workflow from dig results to threat detection"""
        # Create realistic dig results
        dig_results = {
            "Phishing": CategoryDigResult(
                category="Phishing",
                domains=["phishing1.com", "phishing2.com", "phishing3.com"],
                sampled_count=3,
                sampled_at="2024-01-15T10:00:00Z",
                successful_domains=["phishing1.com", "phishing2.com"],
                failed_domains=[{"domain": "phishing3.com", "error": "NXDOMAIN"}],
                dig_results={
                    "phishing1.com": DigResult(
                        domain="phishing1.com", 
                        status="success", 
                        output="1.2.3.4",
                        error="",
                        dns_server="8.8.8.8",
                        command="dig @8.8.8.8 phishing1.com A +short",
                        execution_time=0.1,
                        timestamp="2024-01-15T10:00:00Z"
                    ),
                    "phishing2.com": DigResult(
                        domain="phishing2.com", 
                        status="success", 
                        output="5.6.7.8",
                        error="",
                        dns_server="8.8.8.8",
                        command="dig @8.8.8.8 phishing2.com A +short",
                        execution_time=0.2,
                        timestamp="2024-01-15T10:00:01Z"
                    )
                },
                dig_summary={"total": 3, "successful": 2, "failed": 1, "success_rate": 66.7}
            ),
            "Command_&_Control": CategoryDigResult(
                category="Command_&_Control",
                domains=["c2-1.com", "c2-2.com"],
                sampled_count=2,
                sampled_at="2024-01-15T10:00:00Z",
                successful_domains=["c2-1.com"],
                failed_domains=[{"domain": "c2-2.com", "error": "TIMEOUT"}],
                dig_results={
                    "c2-1.com": DigResult(
                        domain="c2-1.com", 
                        status="success", 
                        output="9.8.7.6",
                        error="",
                        dns_server="8.8.8.8",
                        command="dig @8.8.8.8 c2-1.com A +short",
                        execution_time=0.1,
                        timestamp="2024-01-15T10:00:00Z"
                    )
                },
                dig_summary={"total": 2, "successful": 1, "failed": 1, "success_rate": 50.0}
            )
        }
        
        # Fetch threats
        fetcher = ThreatEventFetcher(mode="simulation", vm_instance_id="test-vm")
        threat_results = fetcher.fetch_threats_for_categories(dig_results)
        
        # Validate results
        self.assertEqual(len(threat_results), 2)
        
        for category, result in threat_results.items():
            # Check basic structure
            self.assertIsInstance(result, CategoryThreatResult)
            self.assertEqual(result.category, category)
            
            # Check threat summary
            summary = result.threat_summary
            self.assertIn("total_successful_domains", summary)
            self.assertIn("detected_domains_count", summary)
            self.assertIn("undetected_domains_count", summary)
            self.assertIn("detection_rate", summary)
            self.assertIn("threat_events_count", summary)
            
            # Validate detection rate calculation
            total = summary["total_successful_domains"]
            detected = summary["detected_domains_count"]
            undetected = summary["undetected_domains_count"]
            rate = summary["detection_rate"]
            
            self.assertEqual(detected + undetected, total)
            if total > 0:
                expected_rate = (detected / total) * 100
                self.assertAlmostEqual(rate, expected_rate, places=1)
            else:
                self.assertEqual(rate, 0.0)
            
            # Check domain lists
            self.assertEqual(len(result.detected_domains), detected)
            self.assertEqual(len(result.undetected_domains), undetected)
            
            # All detected/undetected domains should be in successful_domains
            all_threat_domains = set(result.detected_domains + result.undetected_domains)
            successful_domains_set = set(result.successful_domains)
            self.assertTrue(all_threat_domains.issubset(successful_domains_set))


if __name__ == '__main__':
    unittest.main()