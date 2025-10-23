"""
Threat Detection Simulator v2 - GCP Utilities Module

This module provides utilities for interacting with Google Cloud Platform services,
including automatic VM metadata detection, Cloud Logging integration, and GCP authentication.

Key features:
- Automatic VM metadata detection from GCP metadata server
- Fallback to gcloud commands if metadata server is unavailable  
- Cloud Logging API integration for threat event retrieval
- Service account and permissions validation
- GCP environment setup and validation

This module replicates and extends the functionality from v1 with improved error handling
and better integration with the v2 architecture.
"""

import json
import logging
import subprocess
import socket
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

# Configuration constants
METADATA_SERVER_URL = "http://metadata.google.internal/computeMetadata/v1"
METADATA_HEADERS = {"Metadata-Flavor": "Google"}
METADATA_TIMEOUT = 5
GCLOUD_TIMEOUT = 60  # Increased from 10 to 60 seconds to handle slow gcloud responses


class GCPError(Exception):
    """Base exception for GCP-related errors"""
    pass


class MetadataServerError(GCPError):
    """Exception raised when metadata server is unreachable or returns errors"""
    pass


class GCloudError(GCPError):
    """Exception raised when gcloud commands fail"""
    pass


def get_vm_metadata() -> Dict[str, str]:
    """
    Dynamically get VM metadata from GCP metadata server.
    This function runs on the VM and retrieves its own metadata.
    
    Returns:
        Dict[str, str]: VM metadata including instance_id, project_id, zone, name, region
        
    Raises:
        MetadataServerError: If metadata server is unreachable or returns errors
    """
    metadata = {}
    
    try:
        logger.info("🔍 Detecting VM metadata from GCP metadata server...")
        
        # Get project ID
        try:
            response = _make_metadata_request("/project/project-id")
            metadata['project_id'] = response.strip()
            logger.info(f"✅ Project ID: {metadata['project_id']}")
        except Exception as e:
            logger.warning(f"⚠️ Could not get project ID: {e}")
        
        # Get instance ID (numeric)
        try:
            response = _make_metadata_request("/instance/id")
            metadata['instance_id'] = response.strip()
            logger.info(f"✅ Instance ID: {metadata['instance_id']}")
        except Exception as e:
            logger.warning(f"⚠️ Could not get instance ID: {e}")
        
        # Get instance name
        try:
            response = _make_metadata_request("/instance/name")
            metadata['name'] = response.strip()
            logger.info(f"✅ Instance Name: {metadata['name']}")
        except Exception as e:
            logger.warning(f"⚠️ Could not get instance name: {e}")
        
        # Get zone
        try:
            response = _make_metadata_request("/instance/zone")
            # Zone comes as projects/{project}/zones/{zone}, extract just the zone
            zone_full = response.strip()
            metadata['zone'] = zone_full.split('/')[-1]
            logger.info(f"✅ Zone: {metadata['zone']}")
        except Exception as e:
            logger.warning(f"⚠️ Could not get zone: {e}")
        
        # Derive region from zone
        if 'zone' in metadata:
            # Region is zone minus the last part (e.g., us-central1-a -> us-central1)
            zone_parts = metadata['zone'].rsplit('-', 1)
            if len(zone_parts) > 1:
                metadata['region'] = zone_parts[0]
                logger.info(f"✅ Region: {metadata['region']}")
        
        # Get service account email
        try:
            response = _make_metadata_request("/instance/service-accounts/default/email")
            metadata['service_account_email'] = response.strip()
            logger.info(f"✅ Service Account: {metadata['service_account_email']}")
        except Exception as e:
            logger.warning(f"⚠️ Could not get service account email: {e}")
        
        # Get machine type
        try:
            response = _make_metadata_request("/instance/machine-type")
            # Machine type comes as projects/{project}/machineTypes/{type}, extract just the type
            machine_type_full = response.strip()
            metadata['machine_type'] = machine_type_full.split('/')[-1]
            logger.info(f"✅ Machine Type: {metadata['machine_type']}")
        except Exception as e:
            logger.warning(f"⚠️ Could not get machine type: {e}")
        
        # Validate we got the essential information
        required_fields = ['project_id', 'instance_id', 'zone', 'name']
        missing_fields = [field for field in required_fields if field not in metadata]
        
        if missing_fields:
            error_msg = f"Missing required VM metadata fields: {missing_fields}"
            logger.error(f"❌ {error_msg}")
            logger.error("   This script must run on a GCP VM with metadata server access")
            raise MetadataServerError(error_msg)
        
        logger.info("✅ VM metadata detection successful!")
        return metadata
        
    except MetadataServerError:
        raise
    except Exception as e:
        error_msg = f"Failed to get VM metadata from GCP metadata server: {e}"
        logger.error(f"❌ {error_msg}")
        logger.error("   This script must run on a GCP VM with metadata server access")
        raise MetadataServerError(error_msg)


def _make_metadata_request(path: str, timeout: int = METADATA_TIMEOUT) -> str:
    """
    Make a request to the GCP metadata server
    
    Args:
        path: Metadata endpoint path (e.g., "/instance/id")
        timeout: Request timeout in seconds
        
    Returns:
        str: Response text from metadata server
        
    Raises:
        MetadataServerError: If request fails
    """
    try:
        url = f"{METADATA_SERVER_URL}{path}"
        request = urllib.request.Request(url, headers=METADATA_HEADERS)
        
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status == 200:
                return response.read().decode('utf-8')
            else:
                raise MetadataServerError(f"Metadata server returned status {response.status}")
                
    except (urllib.error.URLError, socket.timeout) as e:
        raise MetadataServerError(f"Cannot reach metadata server: {e}")
    except Exception as e:
        raise MetadataServerError(f"Metadata request failed: {e}")


def get_vm_metadata_with_gcloud_fallback() -> Dict[str, str]:
    """
    Get VM metadata with fallback to gcloud commands if metadata server fails.
    
    Returns:
        Dict[str, str]: VM metadata including instance_id, project_id, zone, name
        
    Raises:
        GCPError: If both metadata server and gcloud fallback fail
    """
    # Try metadata server first
    try:
        metadata = get_vm_metadata()
        logger.info("✅ VM metadata retrieved from metadata server")
        return metadata
    except MetadataServerError as e:
        logger.warning(f"⚠️ Metadata server failed: {e}")
    
    logger.info("🔄 Metadata server failed, trying gcloud commands as fallback...")
    
    try:
        metadata = _get_metadata_via_gcloud()
        logger.info("✅ VM metadata retrieved via gcloud fallback")
        return metadata
    except GCloudError as e:
        logger.error(f"❌ gcloud fallback also failed: {e}")
        raise GCPError("Both metadata server and gcloud fallback failed")


def _get_metadata_via_gcloud() -> Dict[str, str]:
    """
    Get VM metadata using gcloud commands as fallback
    
    Returns:
        Dict[str, str]: VM metadata
        
    Raises:
        GCloudError: If gcloud commands fail
    """
    metadata = {}
    
    try:
        # Get current project
        metadata = _get_project_via_gcloud(metadata)
        
        # Get current VM info by querying the instance we're running on
        metadata = _get_instance_info_via_gcloud(metadata)
        
        # Validate we got essential information
        required_fields = ['project_id']
        missing_fields = [field for field in required_fields if field not in metadata]
        
        if missing_fields:
            error_msg = f"Could not retrieve required metadata via gcloud: {missing_fields}"
            raise GCloudError(error_msg)
        
        return metadata
        
    except GCloudError:
        raise
    except Exception as e:
        raise GCloudError(f"gcloud fallback failed: {e}")


def _get_project_via_gcloud(metadata: Dict[str, str]) -> Dict[str, str]:
    """Get project ID via gcloud"""
    try:
        result = _run_gcloud_command(["gcloud", "config", "get-value", "project"])
        if result.strip():
            metadata['project_id'] = result.strip()
            logger.info(f"✅ Project ID (gcloud): {metadata['project_id']}")
    except Exception as e:
        logger.warning(f"⚠️ Could not get project via gcloud: {e}")
    return metadata


def _get_instance_info_via_gcloud(metadata: Dict[str, str]) -> Dict[str, str]:
    """Get instance information via gcloud"""
    try:
        # Get hostname first
        hostname_result = subprocess.run(
            ["hostname"], capture_output=True, text=True, timeout=5
        )
        if hostname_result.returncode == 0:
            hostname = hostname_result.stdout.strip()
            logger.info(f"📍 Hostname: {hostname}")
            
            # Try to find this instance in the current project
            if 'project_id' in metadata:
                metadata = _query_instance_details(metadata, hostname)
    
    except Exception as e:
        logger.warning(f"⚠️ Could not get instance details via gcloud: {e}")
    
    return metadata


def _query_instance_details(metadata: Dict[str, str], hostname: str) -> Dict[str, str]:
    """Query instance details from gcloud"""
    try:
        list_result = _run_gcloud_command([
            "gcloud", "compute", "instances", "list",
            f"--project={metadata['project_id']}",
            "--format=json",
            f"--filter=name:{hostname}"
        ])
        
        instances = json.loads(list_result)
        if instances and len(instances) > 0:
            instance = instances[0]
            
            # Extract instance ID (numeric ID)
            metadata['instance_id'] = str(instance.get('id', ''))
            metadata['name'] = instance.get('name', hostname)
            
            # Extract zone from full zone URL
            zone_url = instance.get('zone', '')
            if zone_url:
                metadata['zone'] = zone_url.split('/')[-1]
                # Derive region from zone
                zone_parts = metadata['zone'].rsplit('-', 1)
                if len(zone_parts) > 1:
                    metadata['region'] = zone_parts[0]
            
            # Extract machine type
            machine_type_url = instance.get('machineType', '')
            if machine_type_url:
                metadata['machine_type'] = machine_type_url.split('/')[-1]
            
            logger.info("✅ Instance details found via gcloud")
    
    except Exception as e:
        logger.warning(f"⚠️ Could not query instance details: {e}")
    
    return metadata


def _run_gcloud_command(command: List[str], timeout: int = GCLOUD_TIMEOUT) -> str:
    """
    Run a gcloud command and return stdout
    
    Args:
        command: gcloud command as list of strings
        timeout: Command timeout in seconds
        
    Returns:
        str: Command stdout
        
    Raises:
        GCloudError: If command fails
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        return result.stdout
        
    except subprocess.CalledProcessError as e:
        raise GCloudError(f"gcloud command failed: {e.stderr}")
    except subprocess.TimeoutExpired:
        raise GCloudError(f"gcloud command timed out after {timeout}s")
    except FileNotFoundError:
        raise GCloudError("gcloud CLI not found")
    except Exception as e:
        raise GCloudError(f"gcloud command error: {e}")


def validate_gcp_environment() -> Tuple[bool, List[str]]:
    """
    Validate the current GCP environment and return status
    
    Returns:
        Tuple[bool, List[str]]: (is_valid, list_of_issues)
    """
    issues = []
    
    try:
        # Test metadata server accessibility
        try:
            _make_metadata_request("/instance/id", timeout=3)
        except MetadataServerError as e:
            issues.append(f"Metadata server not accessible: {e}")
        
        # Test gcloud availability
        try:
            _run_gcloud_command(["gcloud", "version"], timeout=60)
        except GCloudError as e:
            issues.append(f"gcloud CLI not available: {e}")
        
        # Test current project configuration
        try:
            result = _run_gcloud_command(["gcloud", "config", "get-value", "project"], timeout=60)
            if not result.strip():
                issues.append("No default project configured in gcloud")
        except GCloudError as e:
            issues.append(f"Cannot get current project: {e}")
        
    except Exception as e:
        issues.append(f"Environment validation failed: {e}")
    
    return len(issues) == 0, issues


def get_service_account_scopes() -> List[str]:
    """
    Get the OAuth scopes for the current service account
    
    Returns:
        List[str]: List of OAuth scope URLs
        
    Raises:
        MetadataServerError: If cannot retrieve scopes
    """
    try:
        response = _make_metadata_request("/instance/service-accounts/default/scopes")
        scopes = [scope.strip() for scope in response.strip().split('\n') if scope.strip()]
        logger.info(f"✅ Retrieved {len(scopes)} service account scopes")
        return scopes
        
    except Exception as e:
        raise MetadataServerError(f"Cannot retrieve service account scopes: {e}")


def check_required_scopes(required_scopes: Optional[List[str]] = None) -> Tuple[bool, List[str], List[str]]:
    """
    Check if the current service account has required OAuth scopes
    
    Args:
        required_scopes: List of required scope URLs. If None, uses default Cloud Logging scopes.
        
    Returns:
        Tuple[bool, List[str], List[str]]: (has_all_scopes, present_scopes, missing_scopes)
    """
    if required_scopes is None:
        required_scopes = [
            "https://www.googleapis.com/auth/logging.read",
            "https://www.googleapis.com/auth/cloud-platform"
        ]
    
    try:
        current_scopes = get_service_account_scopes()
        
        # Check for exact matches or cloud-platform (which includes everything)
        present_scopes = []
        missing_scopes = []
        
        has_cloud_platform = any("cloud-platform" in scope for scope in current_scopes)
        
        for required_scope in required_scopes:
            if required_scope in current_scopes or has_cloud_platform:
                present_scopes.append(required_scope)
            else:
                # Check for partial matches (e.g., logging scope variants)
                if any(required_scope.split('/')[-1] in scope for scope in current_scopes):
                    present_scopes.append(required_scope)
                else:
                    missing_scopes.append(required_scope)
        
        has_all = len(missing_scopes) == 0
        
        if has_all:
            logger.info("✅ All required OAuth scopes are present")
        else:
            logger.warning(f"⚠️ Missing OAuth scopes: {missing_scopes}")
        
        return has_all, present_scopes, missing_scopes
        
    except Exception as e:
        logger.error(f"❌ Cannot check OAuth scopes: {e}")
        return False, [], required_scopes


def get_vm_metadata_for_threat_fetcher() -> Dict[str, str]:
    """
    Get VM metadata specifically formatted for ThreatEventFetcher initialization
    
    Returns:
        Dict[str, str]: Metadata with keys: project_id, vm_instance_id, vm_zone
        
    Raises:
        GCPError: If metadata cannot be retrieved
    """
    try:
        metadata = get_vm_metadata_with_gcloud_fallback()
        
        # Map to ThreatEventFetcher expected format
        threat_fetcher_metadata = {
            'project_id': metadata.get('project_id', ''),
            'vm_instance_id': metadata.get('instance_id', ''),
            'vm_zone': metadata.get('zone', '')
        }
        
        # Validate required fields for threat fetcher
        missing_fields = [k for k, v in threat_fetcher_metadata.items() if not v]
        if missing_fields:
            raise GCPError(f"Missing required fields for ThreatEventFetcher: {missing_fields}")
        
        logger.info("✅ VM metadata formatted for ThreatEventFetcher")
        return threat_fetcher_metadata
        
    except Exception as e:
        logger.error(f"❌ Cannot get VM metadata for ThreatEventFetcher: {e}")
        raise GCPError(f"ThreatEventFetcher metadata retrieval failed: {e}")


def test_cloud_logging_access(project_id: Optional[str] = None, 
                            vm_instance_id: Optional[str] = None) -> bool:
    """
    Test Cloud Logging API access with a simple query
    
    Args:
        project_id: GCP project ID (auto-detected if None)
        vm_instance_id: VM instance ID for filtering (auto-detected if None)
        
    Returns:
        bool: True if Cloud Logging access works
    """
    try:
        # Auto-detect metadata if not provided
        if not project_id or not vm_instance_id:
            try:
                metadata = get_vm_metadata_for_threat_fetcher()
                project_id = project_id or metadata['project_id']
                vm_instance_id = vm_instance_id or metadata['vm_instance_id']
            except Exception as e:
                logger.warning(f"⚠️ Could not auto-detect metadata for logging test: {e}")
                return False
        
        # Simple gcloud logging read test
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=5)
        
        test_command = [
            "gcloud", "logging", "read",
            f'timestamp>="{start_time.strftime("%Y-%m-%dT%H:%M:%SZ")}"',
            f"--project={project_id}",
            "--limit=1",
            "--format=json",
            "--quiet"
        ]
        
        _run_gcloud_command(test_command, timeout=30)
        
        # If we get here without exception, logging access works
        logger.info("✅ Cloud Logging API access test successful")
        return True
        
    except Exception as e:
        logger.warning(f"⚠️ Cloud Logging API access test failed: {e}")
        return False


def get_comprehensive_vm_info() -> Dict[str, any]:  # type: ignore
    """
    Get comprehensive VM information including metadata, environment validation, and permissions
    
    Returns:
        Dict containing all VM info, validation results, and permission status
    """
    info = {
        'metadata': {},
        'environment_valid': False,
        'environment_issues': [],
        'has_required_scopes': False,
        'present_scopes': [],
        'missing_scopes': [],
        'cloud_logging_access': False,
        'detection_method': 'unknown'
    }
    
    try:
        # Get VM metadata
        try:
            info['metadata'] = get_vm_metadata()
            info['detection_method'] = 'metadata_server'
        except MetadataServerError:
            try:
                info['metadata'] = _get_metadata_via_gcloud()
                info['detection_method'] = 'gcloud_fallback'
            except GCloudError:
                logger.error("❌ Both metadata detection methods failed")
        
        # Validate environment
        info['environment_valid'], info['environment_issues'] = validate_gcp_environment()
        
        # Check OAuth scopes
        try:
            has_scopes, present, missing = check_required_scopes()
            info['has_required_scopes'] = has_scopes
            info['present_scopes'] = present
            info['missing_scopes'] = missing
        except Exception as e:
            logger.warning(f"⚠️ Could not check OAuth scopes: {e}")
        
        # Test Cloud Logging access
        try:
            info['cloud_logging_access'] = test_cloud_logging_access(
                info['metadata'].get('project_id'),
                info['metadata'].get('instance_id')
            )
        except Exception as e:
            logger.warning(f"⚠️ Could not test Cloud Logging access: {e}")
        
        return info
        
    except Exception as e:
        logger.error(f"❌ Comprehensive VM info collection failed: {e}")
        info['error'] = str(e)
        return info


# Convenience functions for backward compatibility and easy integration
def auto_configure_threat_fetcher():
    """
    Automatically configure ThreatEventFetcher with VM metadata
    
    Returns:
        Tuple[str, str, str]: (project_id, vm_instance_id, vm_zone)
        
    Raises:
        GCPError: If auto-configuration fails
    """
    try:
        metadata = get_vm_metadata_for_threat_fetcher()
        return (
            metadata['project_id'],
            metadata['vm_instance_id'], 
            metadata['vm_zone']
        )
    except Exception as e:
        raise GCPError(f"Auto-configuration failed: {e}")


if __name__ == "__main__":
    # Test the module functionality
    import logging
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("🧪 Testing GCP Utils Module")
    print("=" * 50)
    
    try:
        # Test comprehensive VM info
        info = get_comprehensive_vm_info()
        
        print(f"\n📋 VM Metadata (via {info['detection_method']}):")
        for key, value in info['metadata'].items():
            print(f"  {key}: {value}")
        
        print(f"\n🔍 Environment Valid: {info['environment_valid']}")
        if info['environment_issues']:
            print("⚠️ Issues found:")
            for issue in info['environment_issues']:
                print(f"  - {issue}")
        
        print(f"\n🔑 OAuth Scopes: {'✅ Valid' if info['has_required_scopes'] else '❌ Missing'}")
        if info['missing_scopes']:
            print("❌ Missing scopes:")
            for scope in info['missing_scopes']:
                print(f"  - {scope}")
        
        print(f"\n📊 Cloud Logging Access: {'✅ Working' if info['cloud_logging_access'] else '❌ Failed'}")
        
        # Test ThreatEventFetcher auto-configuration
        print("\n🎯 ThreatEventFetcher Auto-Configuration:")
        try:
            project_id, vm_instance_id, vm_zone = auto_configure_threat_fetcher()
            print(f"  Project: {project_id}")
            print(f"  VM Instance: {vm_instance_id}")
            print(f"  Zone: {vm_zone}")
            print("✅ Auto-configuration successful!")
        except Exception as e:
            print(f"❌ Auto-configuration failed: {e}")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")