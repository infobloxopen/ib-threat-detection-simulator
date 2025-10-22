"""
Threat Detection Simulator v2 - Dependency Checker Module

Comprehensive pre-flight dependency validation for the threat detection simulator.
Validates system requirements, tools, GCP environment, and Python dependencies
to ensure the simulator can run successfully.

This module replicates and extends the preflight_checks functionality from v1 run.sh
with improved Python-based validation and better error reporting.
"""

import logging
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional

# Import GCP utilities for enhanced environment validation
try:
    from .gcp_utils import validate_gcp_environment, get_comprehensive_vm_info
    GCP_UTILS_AVAILABLE = True
except ImportError:
    GCP_UTILS_AVAILABLE = False

logger = logging.getLogger(__name__)

import os
import sys
import subprocess
import shutil
import logging
import socket
from typing import Dict, List, Tuple, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class DependencyCheckResult:
    """Results from dependency checking"""
    
    def __init__(self):
        self.passed: bool = True
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.info: List[str] = []
        self.checks_performed: Dict[str, bool] = {}
    
    def add_error(self, message: str, check_name: str = ""):
        """Add an error that prevents execution"""
        self.errors.append(message)
        self.passed = False
        if check_name:
            self.checks_performed[check_name] = False
        logger.error(f"❌ {message}")
    
    def add_warning(self, message: str, check_name: str = ""):
        """Add a warning that doesn't prevent execution"""
        self.warnings.append(message)
        if check_name:
            self.checks_performed[check_name] = True
        logger.warning(f"⚠️ {message}")
    
    def add_success(self, message: str, check_name: str = ""):
        """Add a successful check result"""
        self.info.append(message)
        if check_name:
            self.checks_performed[check_name] = True
        logger.info(f"✅ {message}")


class DependencyChecker:
    """Comprehensive dependency and environment checker for threat detection simulator"""
    
    def __init__(self, skip_preflight: bool = False):
        self.skip_preflight = skip_preflight
        self.result = DependencyCheckResult()
    
    def run_full_check(self) -> DependencyCheckResult:
        """
        Run comprehensive dependency checks including enhanced GCP validation
        
        Returns:
            DependencyCheckResult: Complete validation results
        """
        logger.info("🔍 Running comprehensive dependency checks...")
        
        # Core system checks
        self._check_python_version()
        self._check_dns_tools()
        self._check_gcloud_cli()
        self._check_metadata_server()
        self._check_service_account()
        self._check_cloud_logging_access()
        
        # Enhanced GCP validation if available
        if GCP_UTILS_AVAILABLE:
            self._enhanced_gcp_validation()
        else:
            self.result.add_warning(
                "Enhanced GCP validation unavailable (gcp_utils not imported)",
                "enhanced_gcp"
            )
        
        # Log summary
        self._log_check_summary()
        
        return self.result
    
    def _enhanced_gcp_validation(self) -> None:
        """Enhanced GCP environment validation using gcp_utils"""
        try:
            logger.info("🔍 Running enhanced GCP environment validation...")
            
            # Get comprehensive VM info
            vm_info = get_comprehensive_vm_info()
            
            # Validate environment
            if vm_info.get('environment_valid', False):
                self.result.add_success(
                    f"Enhanced GCP environment validation passed (method: {vm_info.get('detection_method', 'unknown')})",
                    "enhanced_gcp_env"
                )
            else:
                issues = vm_info.get('environment_issues', [])
                self.result.add_error(
                    f"Enhanced GCP environment validation failed: {'; '.join(issues)}",
                    "enhanced_gcp_env"
                )
            
            # Check VM metadata detection
            metadata = vm_info.get('metadata', {})
            if metadata:
                required_fields = ['project_id', 'instance_id', 'zone']
                present_fields = [field for field in required_fields if metadata.get(field)]
                
                if len(present_fields) == len(required_fields):
                    self.result.add_success(
                        f"VM metadata complete: project={metadata.get('project_id')}, "
                        f"instance={metadata.get('instance_id')}, zone={metadata.get('zone')}",
                        "vm_metadata"
                    )
                else:
                    missing = [field for field in required_fields if not metadata.get(field)]
                    self.result.add_warning(
                        f"VM metadata incomplete, missing: {', '.join(missing)}",
                        "vm_metadata"
                    )
            
            # Check OAuth scopes
            if vm_info.get('has_required_scopes', False):
                self.result.add_success(
                    "Required OAuth scopes verified",
                    "oauth_scopes"
                )
            else:
                missing_scopes = vm_info.get('missing_scopes', [])
                if missing_scopes:
                    self.result.add_warning(
                        f"Missing OAuth scopes: {', '.join(s.split('/')[-1] for s in missing_scopes)}",
                        "oauth_scopes"
                    )
            
            # Check Cloud Logging access
            if vm_info.get('cloud_logging_access', False):
                self.result.add_success(
                    "Cloud Logging API access verified",
                    "cloud_logging_api"
                )
            else:
                self.result.add_warning(
                    "Cloud Logging API access test failed",
                    "cloud_logging_api"
                )
                
        except Exception as e:
            self.result.add_warning(f"Enhanced GCP validation failed: {e}", "enhanced_gcp")
    
    def _log_check_summary(self) -> None:
        """Log a summary of the dependency check results"""
        total_checks = len(self.result.info) + len(self.result.warnings) + len(self.result.errors)
        
        logger.info("📊 Dependency check summary:")
        logger.info(f"   Total checks: {total_checks}")
        logger.info(f"   ✅ Successes: {len(self.result.info)}")
        logger.info(f"   ⚠️ Warnings: {len(self.result.warnings)}")
        logger.info(f"   ❌ Errors: {len(self.result.errors)}")
        
        if self.result.passed:
            logger.info("🎉 All critical dependency checks passed!")
        else:
            logger.error("💥 Critical dependency checks failed!")
            logger.error("Fix the errors above or set SKIP_PREFLIGHT=1 to override")
    
    def _check_python_version(self) -> None:
        """Check Python version compatibility"""
        try:
            version_info = sys.version_info
            version_str = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
            
            if version_info.major < 3 or (version_info.major == 3 and version_info.minor < 8):
                self.result.add_error(
                    f"Python 3.8+ required, found {version_str}",
                    "python_version"
                )
            else:
                self.result.add_success(
                    f"Python version OK: {version_str}",
                    "python_version"
                )
        except Exception as e:
            self.result.add_error(f"Failed to check Python version: {e}", "python_version")
    
    def _check_dns_tools(self) -> None:
        """Check availability of DNS tools (dig, host, nslookup)"""
        tools = ["dig", "host", "nslookup"]
        found_tools = []
        
        for tool in tools:
            if shutil.which(tool):
                found_tools.append(tool)
                logger.debug(f"Found {tool}: {shutil.which(tool)}")
        
        if "dig" in found_tools:
            self.result.add_success(
                f"dig found: {shutil.which('dig')}",
                "dns_tools"
            )
        elif found_tools:
            self.result.add_warning(
                f"dig not found, but have alternatives: {', '.join(found_tools)}",
                "dns_tools"
            )
        else:
            self.result.add_error(
                "No DNS tools found (install dnsutils/bind-tools package)",
                "dns_tools"
            )
    
    def _check_gcloud_cli(self) -> None:
        """Check Google Cloud CLI availability and authentication"""
        gcloud_path = shutil.which("gcloud")
        
        if not gcloud_path:
            # Try common installation paths
            common_paths = [
                "/usr/bin/gcloud",
                "/usr/local/bin/gcloud",
                "/opt/homebrew/bin/gcloud",
                os.path.expanduser("~/google-cloud-sdk/bin/gcloud"),
                "/snap/bin/gcloud"
            ]
            
            for path in common_paths:
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    gcloud_path = path
                    break
        
        if gcloud_path:
            try:
                # Test gcloud version
                result = subprocess.run(
                    [gcloud_path, "version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode == 0:
                    self.result.add_success(
                        f"gcloud found: {gcloud_path}",
                        "gcloud_cli"
                    )
                    
                    # Check authentication
                    auth_result = subprocess.run(
                        [gcloud_path, "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"],
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if auth_result.returncode == 0 and auth_result.stdout.strip():
                        self.result.add_success(
                            f"gcloud authenticated as: {auth_result.stdout.strip()}",
                            "gcloud_auth"
                        )
                    else:
                        self.result.add_warning(
                            "gcloud not authenticated (run 'gcloud auth login')",
                            "gcloud_auth"
                        )
                else:
                    self.result.add_error(f"gcloud CLI test failed: {result.stderr}", "gcloud_cli")
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                self.result.add_error(f"gcloud CLI test failed: {e}", "gcloud_cli")
        else:
            self.result.add_error(
                "gcloud CLI not found (install Google Cloud SDK)",
                "gcloud_cli"
            )
    
    def _check_metadata_server(self) -> None:
        """Check GCP metadata server accessibility"""
        try:
            import urllib.request
            import urllib.error
            
            request = urllib.request.Request(
                "http://metadata.google.internal/computeMetadata/v1/instance/id",
                headers={"Metadata-Flavor": "Google"}
            )
            
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status == 200:
                    instance_id = response.read().decode('utf-8')
                    self.result.add_success(
                        f"Metadata server reachable (Instance ID: {instance_id})",
                        "metadata_server"
                    )
                else:
                    self.result.add_error(
                        f"Metadata server returned status {response.status}",
                        "metadata_server"
                    )
        except (urllib.error.URLError, socket.timeout) as e:
            self.result.add_error(
                f"Cannot reach metadata server (are you on GCE VM?): {e}",
                "metadata_server"
            )
        except Exception as e:
            self.result.add_error(f"Metadata server check failed: {e}", "metadata_server")
    
    def _check_service_account(self) -> None:
        """Check service account configuration"""
        try:
            import urllib.request
            import urllib.error
            
            # Get service account email
            request = urllib.request.Request(
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
                headers={"Metadata-Flavor": "Google"}
            )
            
            with urllib.request.urlopen(request, timeout=5) as response:
                if response.status == 200:
                    sa_email = response.read().decode('utf-8')
                    self.result.add_success(
                        f"Service Account: {sa_email}",
                        "service_account"
                    )
                    
                    # Check scopes
                    scope_request = urllib.request.Request(
                        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
                        headers={"Metadata-Flavor": "Google"}
                    )
                    
                    with urllib.request.urlopen(scope_request, timeout=5) as scope_response:
                        scopes = scope_response.read().decode('utf-8').strip().split('\\n')
                        
                        # Check for required scopes
                        has_logging = any("logging" in scope for scope in scopes)
                        has_cloud_platform = any("cloud-platform" in scope for scope in scopes)
                        
                        if has_logging or has_cloud_platform:
                            self.result.add_success(
                                "Service account has required scopes for Cloud Logging",
                                "service_account_scopes"
                            )
                        else:
                            self.result.add_warning(
                                "Service account may lack Cloud Logging scopes",
                                "service_account_scopes"
                            )
                else:
                    self.result.add_error(
                        "Unable to retrieve service account email",
                        "service_account"
                    )
        except Exception as e:
            self.result.add_warning(f"Service account check failed: {e}", "service_account")
    
    def _check_cloud_logging_access(self) -> None:
        """Test Cloud Logging API access"""
        gcloud_path = shutil.which("gcloud")
        if not gcloud_path:
            self.result.add_warning("Cannot test Cloud Logging (gcloud not found)", "cloud_logging")
            return
        
        try:
            # Quick test of Cloud Logging read access
            result = subprocess.run(
                [gcloud_path, "logging", "read", 'timestamp>="-5m"', "--limit=1", "--quiet"],
                capture_output=True,
                text=True,
                timeout=15
            )
            
            if result.returncode == 0:
                self.result.add_success(
                    "Cloud Logging read access OK",
                    "cloud_logging"
                )
            else:
                self.result.add_warning(
                    f"Cloud Logging read test failed (may lack roles/logging.viewer): {result.stderr}",
                    "cloud_logging"
                )
        except subprocess.TimeoutExpired:
            self.result.add_warning("Cloud Logging test timed out", "cloud_logging")
        except Exception as e:
            self.result.add_warning(f"Cloud Logging test failed: {e}", "cloud_logging")
    
    def _check_vpc_dns(self) -> None:
        """Check VPC DNS functionality"""
        dig_path = shutil.which("dig")
        if not dig_path:
            self.result.add_warning("Cannot test VPC DNS (dig not found)", "vpc_dns")
            return
        
        try:
            # Test DNS query via VPC resolver
            result = subprocess.run(
                [dig_path, "@169.254.169.254", "example.com", "+short"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                self.result.add_success(
                    "VPC DNS query successful",
                    "vpc_dns"
                )
            else:
                self.result.add_warning(
                    "DNS via 169.254.169.254 failed (custom resolver?)",
                    "vpc_dns"
                )
        except subprocess.TimeoutExpired:
            self.result.add_warning("VPC DNS test timed out", "vpc_dns")
        except Exception as e:
            self.result.add_warning(f"VPC DNS test failed: {e}", "vpc_dns")
    
    def _check_internet_connectivity(self) -> None:
        """Check internet connectivity for external DNS queries"""
        try:
            # Test connectivity to Google's public DNS
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.connect(("8.8.8.8", 53))
            sock.close()
            
            self.result.add_success(
                "Internet connectivity OK (8.8.8.8:53 reachable)",
                "internet_connectivity"
            )
        except Exception as e:
            self.result.add_warning(
                f"Internet connectivity test failed: {e}",
                "internet_connectivity"
            )
    
    def _check_python_packages(self) -> None:
        """Check required Python packages"""
        required_packages = [
            "json",
            "logging", 
            "datetime",
            "pathlib",
            "subprocess",
            "hashlib",
            "random"
        ]
        
        missing_packages = []
        
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                missing_packages.append(package)
        
        if missing_packages:
            self.result.add_error(
                f"Missing Python packages: {', '.join(missing_packages)}",
                "python_packages"
            )
        else:
            self.result.add_success(
                "All required Python packages available",
                "python_packages"
            )
    
    def _check_file_permissions(self) -> None:
        """Check file system permissions for output directories"""
        try:
            # Check current directory write access
            test_file = Path(".") / "test_write_permissions.tmp"
            test_file.write_text("test")
            test_file.unlink()
            
            self.result.add_success(
                "File system write permissions OK",
                "file_permissions"
            )
        except Exception as e:
            self.result.add_error(
                f"Cannot write to current directory: {e}",
                "file_permissions"
            )
    
    def _log_summary(self) -> None:
        """Log summary of all checks"""
        total_checks = len(self.result.checks_performed)
        passed_checks = sum(1 for passed in self.result.checks_performed.values() if passed)
        
        logger.info("\\n" + "="*60)
        logger.info("🏁 Pre-flight Check Summary")
        logger.info("="*60)
        
        if self.result.passed:
            logger.info(f"✅ All critical checks passed ({passed_checks}/{total_checks})")
            if self.result.warnings:
                logger.info(f"⚠️ {len(self.result.warnings)} warning(s) - review recommended")
        else:
            logger.error(f"❌ {len(self.result.errors)} critical error(s) found")
            logger.info(f"📊 Checks passed: {passed_checks}/{total_checks}")
        
        # Log details
        if self.result.errors:
            logger.info("\\n🚨 Critical Errors:")
            for error in self.result.errors:
                logger.error(f"   • {error}")
        
        if self.result.warnings:
            logger.info("\\n⚠️ Warnings:")
            for warning in self.result.warnings:
                logger.warning(f"   • {warning}")
        
        logger.info("="*60)


def run_preflight_checks(skip_preflight: bool = False) -> DependencyCheckResult:
    """
    Convenience function to run all pre-flight dependency checks.
    
    Args:
        skip_preflight: If True, skip all checks and return success
        
    Returns:
        DependencyCheckResult: Results of all dependency checks
    """
    checker = DependencyChecker(skip_preflight)
    return checker.run_full_check()


def validate_dependencies_or_exit(skip_preflight: bool = False) -> None:
    """
    Run dependency checks and exit if critical errors are found.
    
    Args:
        skip_preflight: If True, skip all checks
    """
    result = run_preflight_checks(skip_preflight)
    
    if not result.passed:
        logger.error("\\n❌ Pre-flight checks failed!")
        logger.error("Fix the above errors or set SKIP_PREFLIGHT=1 to override.")
        logger.error("Exiting...")
        sys.exit(2)
    
    logger.info("\\n✅ All pre-flight checks passed - ready to execute!")


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run checks
    result = run_preflight_checks()
    
    if result.passed:
        print("\\n✅ All dependency checks passed!")
    else:
        print(f"\\n❌ Dependency checks failed with {len(result.errors)} error(s)")
        sys.exit(1)