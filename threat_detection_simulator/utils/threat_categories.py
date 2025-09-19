"""
Threat Category Mappings for GCP DNS Analysis

Defines the mapping between threat categories and their corresponding 
GCP Cloud Logging filter conditions based on threatId and threatType.
"""

# Threat category to GCP filter mapping
# Each category maps to the specific threatId or threatType used in GCP logs
THREAT_CATEGORY_FILTERS = {
    "Malicious_Generic": {
        "filter_type": "threatId",
        "filter_value": "Malicious_Generic",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Malicious_Generic"'
    },
    "Malicious_TDS": {
        "filter_type": "threatId", 
        "filter_value": "Malicious_TDS",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Malicious_TDS"'
    },
    "Phishing": {
        "filter_type": "threatType",
        "filter_value": "Phishing", 
        "gcp_filter": 'jsonPayload.threatInfo.threatType="Phishing"'
    },
    # Additional categories based on ib-base-category.json file
    "TDS": {
        "filter_type": "threatId",
        "filter_value": "Malicious_TDS",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Malicious_TDS"'
    },
    "Command_&_Control": {
        "filter_type": "threatId",
        "filter_value": "C2",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="C2"'
    },
    "Malicious_Domains": {
        "filter_type": "threatId",
        "filter_value": "Malicious_Generic",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Malicious_Generic"'
    },
    "High_Risk": {
        "filter_type": "threatId",
        "filter_value": "Malicious_Generic",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Malicious_Generic"'
    },
    "Emerging_Domains": {
        "filter_type": "threatId",
        "filter_value": "Malicious_Generic", 
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Malicious_Generic"'
    },
    "Lookalikes": {
        "filter_type": "threatType",
        "filter_value": "Phishing",
        "gcp_filter": 'jsonPayload.threatInfo.threatType="Phishing"'
    },
    "DGAS_&_RDGAS": {
        "filter_type": "threatId",
        "filter_value": "Malicious_Generic",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Malicious_Generic"'
    },
    # Standard threat categories for reference
    "Malware": {
        "filter_type": "threatId",
        "filter_value": "Malware",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Malware"'
    },
    "Botnet": {
        "filter_type": "threatId",
        "filter_value": "Botnet", 
        "gcp_filter": 'jsonPayload.threatInfo.threatId="Botnet"'
    },
    "C2": {
        "filter_type": "threatId",
        "filter_value": "C2",
        "gcp_filter": 'jsonPayload.threatInfo.threatId="C2"'
    }
}

def get_threat_filter(category: str) -> dict:
    """
    Get the threat filter configuration for a given category.
    
    Args:
        category (str): The threat category name
        
    Returns:
        dict: Filter configuration with filter_type, filter_value, and gcp_filter
        None: If category not found
    """
    return THREAT_CATEGORY_FILTERS.get(category)

def get_supported_categories() -> list:
    """
    Get list of all supported threat categories.
    
    Returns:
        list: List of supported category names
    """
    return list(THREAT_CATEGORY_FILTERS.keys())

def is_category_supported(category: str) -> bool:
    """
    Check if a threat category is supported.
    
    Args:
        category (str): The threat category name
        
    Returns:
        bool: True if category is supported, False otherwise
    """
    return category in THREAT_CATEGORY_FILTERS
