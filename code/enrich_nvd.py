import requests
import os
import re
import pandas as pd
import cvss
import logging
from packaging import version

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Data sources
EPSS_CSV = 'data/epss/epss_scores.csv'
METASPLOIT_JSON = 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json'
NUCLEI_JSON = 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json'
EXPLOITDB_CSV = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
POC_GITHUB = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"
VULNCHECK_KEV = 'https://api.vulncheck.com/v3/index/vulncheck-kev'
VULNCHECK_API_KEY = os.environ.get('VULNCHECK_API_KEY')

# Source quality metrics for exploit maturity assessment
SOURCE_QUALITY = {
    'metasploit': {'reliability': 0.9, 'ease': 0.8, 'effectiveness': 0.85},
    'exploitdb': {'reliability': 0.7, 'ease': 0.6, 'effectiveness': 0.7},
    'nuclei': {'reliability': 0.8, 'ease': 0.9, 'effectiveness': 0.75},
    'poc_github': {'reliability': 0.5, 'ease': 0.4, 'effectiveness': 0.6},
    'cisa_kev': {'reliability': 0.95, 'ease': 0.7, 'effectiveness': 0.9},
    'vulncheck_kev': {'reliability': 0.9, 'ease': 0.7, 'effectiveness': 0.85}
}

EPSS_THRESHOLD = 0.36
"""
36% is the threshold correlated to the F1 score of EPSSv3 model
At ~37%, the CVE is very likely to have weaponized exploit code
"""

# CVSS standards definitions - derived from official documentation
CVSS_VERSION_METRICS = {
    '2.0': {
        'exploit_maturity': {
            'high': 'E:H',       # High
            'poc': 'E:POC',      # Proof-of-Concept
            'unproven': 'E:U',   # Unproven
            'default': 'E:U'     # Default value
        },
        'remediation': {
            'official': 'OF',     # Official Fix (without RL: prefix)
            'workaround': 'W',    # Workaround
            'unavailable': 'U',   # Unavailable 
            'default': 'OF'       # Default value
        },
        'confidence': {
            'confirmed': 'C',      # Confirmed (without RC: prefix)
            'uncorroborated': 'UR', # Uncorroborated
            'unconfirmed': 'UC',    # Unconfirmed
            'default': 'C'          # Default value
        }
    },
    '3.0': {
        'exploit_maturity': {
            'high': 'E:H',        # High
            'functional': 'E:F',  # Functional
            'poc': 'E:P',         # Proof-of-Concept
            'unproven': 'E:U',    # Unproven
            'notdefined': 'E:X',  # Not Defined
            'default': 'E:U'      # Default value
        },
        'remediation': {
            'official': 'O',        # Official Fix (without RL: prefix)
            'temporary': 'T',       # Temporary Fix
            'workaround': 'W',      # Workaround
            'unavailable': 'U',     # Unavailable
            'notdefined': 'X',      # Not Defined
            'default': 'O'          # Default value
        },
        'confidence': {
            'confirmed': 'C',       # Confirmed (without RC: prefix)
            'reasonable': 'R',      # Reasonable
            'unknown': 'U',         # Unknown
            'notdefined': 'X',      # Not Defined
            'default': 'C'          # Default value
        }
    },
    '3.1': {
        'exploit_maturity': {
            'high': 'E:H',        # High
            'functional': 'E:F',  # Functional
            'poc': 'E:P',         # Proof-of-Concept
            'unproven': 'E:U',    # Unproven
            'notdefined': 'E:X',  # Not Defined
            'default': 'E:U'      # Default value
        },
        'remediation': {
            'official': 'O',        # Official Fix (without RL: prefix)
            'temporary': 'T',       # Temporary Fix
            'workaround': 'W',      # Workaround
            'unavailable': 'U',     # Unavailable
            'notdefined': 'X',      # Not Defined
            'default': 'O'          # Default value
        },
        'confidence': {
            'confirmed': 'C',       # Confirmed (without RC: prefix)
            'reasonable': 'R',      # Reasonable
            'unknown': 'U',         # Unknown
            'notdefined': 'X',      # Not Defined
            'default': 'C'          # Default value
        }
    },
    '4.0': {
        'exploit_maturity': {
            'attacked': 'E:A',      # Attacked (new in 4.0)
            'poc': 'E:P',           # Proof-of-Concept
            'unreported': 'E:U',    # Unreported (renamed from Unproven)
            'notdefined': 'E:X',    # Not Defined
            'default': 'E:X'        # Default value is Not Defined which maps to Attacked for scoring
        }
    }
}


def safe_request(url, headers=None, max_retries=3):
    """
    Make a request with retry logic and error handling
    """
    retries = 0
    while retries < max_retries:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            retries += 1
            logger.warning(f"Request failed for {url}: {e}. Retry {retries}/{max_retries}")
            if retries == max_retries:
                logger.error(f"Failed to fetch data from {url} after {max_retries} attempts")
                raise
    return None

def enrich(df, epss_df):
    """
    Enrich CVE data with EPSS, KEV, ExploitDB, Metasploit, and Nuclei data
    """
    # Create a metrics collector to track success/failure rates
    metrics = {
        'total_cves': len(df),
        'successful_enrichments': 0,
        'failed_sources': {}
    }

    try:
        #Load KEV Data
        logger.info("Loading CISA KEV data")
        response = safe_request(KEV_JSON)
        kev_json_data = response.json()
        kev_cve_list = []
        for vuln in kev_json_data.get('vulnerabilities', []):
            kev_cve_list.append(vuln.get('cveID'))
        kev_df = pd.DataFrame(kev_cve_list, columns=['cve'])
        kev_df['cisa_kev'] = True
    except Exception as e:
        logger.error(f"Failed to load CISA KEV data: {e}")
        kev_df = pd.DataFrame(columns=['cve', 'cisa_kev'])
        metrics['failed_sources']['cisa_kev'] = str(e)

    try:
        #Load VulnCheck KEV
        logger.info("Loading VulnCheck KEV data")
        if not VULNCHECK_API_KEY:
            logger.warning("VULNCHECK_API_KEY not found in environment variables")
            vulncheck_kev_df = pd.DataFrame(columns=['cve', 'vulncheck_kev'])
            metrics['failed_sources']['vulncheck_kev'] = "API key not found"
        else:
            vulncheck_kev = get_vulncheck_data()
            vulncheck_kev_df = pd.DataFrame(vulncheck_kev, columns=['cve'])
            vulncheck_kev_df['cve'] = vulncheck_kev_df['cve'].apply(lambda x: ', '.join(map(str, x)))
            vulncheck_kev_df['vulncheck_kev'] = True
    except Exception as e:
        logger.error(f"Failed to load VulnCheck KEV data: {e}")
        vulncheck_kev_df = pd.DataFrame(columns=['cve', 'vulncheck_kev'])
        metrics['failed_sources']['vulncheck_kev'] = str(e)

    try:
        #Load ExploitDB
        logger.info("Loading ExploitDB data")
        exploitdb_df = pd.read_csv(EXPLOITDB_CSV, usecols=['codes']).rename(columns={"codes": "cve"})
        exploitdb_df.drop_duplicates(inplace=True)
        exploitdb_df = exploitdb_df['cve'].str.extract(r"(CVE-\d{4}-\d{4,7})", expand=False).dropna().values
        exploitdb_df = pd.DataFrame(exploitdb_df, columns = ['cve'])
        exploitdb_df['exploitdb'] = True
    except Exception as e:
        logger.error(f"Failed to load ExploitDB data: {e}")
        exploitdb_df = pd.DataFrame(columns=['cve', 'exploitdb'])
        metrics['failed_sources']['exploitdb'] = str(e)

    try:
        #Load Metasploit
        logger.info("Loading Metasploit data")
        response = safe_request(METASPLOIT_JSON)
        ms_json_data = response.json()
        ms_cve_list = []
        ms_quality_data = []
        
        for item in ms_json_data:
            if 'references' in ms_json_data[item]:
                cve_references = [ref for ref in ms_json_data[item]['references'] if ref.startswith('CVE-')]
                ms_cve_list.extend(cve_references)
                
                # Extract reliability rating if available
                reliability = ms_json_data[item].get('reliability', 'Unknown')
                rank = ms_json_data[item].get('rank', 'Normal')
                
                # Map ratings to numerical scores
                reliability_score = map_reliability_to_score(reliability)
                rank_score = map_rank_to_score(rank)
                
                for cve in cve_references:
                    ms_quality_data.append({
                        'cve': cve,
                        'metasploit_reliability': reliability_score,
                        'metasploit_rank': rank_score
                    })
                
        metasploit_df = pd.DataFrame(ms_cve_list, columns=['cve'])
        metasploit_df['metasploit'] = True
        
        # Create quality dataframe
        metasploit_quality_df = pd.DataFrame(ms_quality_data)
        if not metasploit_quality_df.empty:
            # If we have duplicate CVEs, take the highest reliability score
            metasploit_quality_df = metasploit_quality_df.sort_values('metasploit_reliability', ascending=False)
            metasploit_quality_df = metasploit_quality_df.drop_duplicates(subset='cve', keep='first')
    except Exception as e:
        logger.error(f"Failed to load Metasploit data: {e}")
        metasploit_df = pd.DataFrame(columns=['cve', 'metasploit'])
        metasploit_quality_df = pd.DataFrame(columns=['cve', 'metasploit_reliability', 'metasploit_rank'])
        metrics['failed_sources']['metasploit'] = str(e)

    try:
        #Load Nuclei
        logger.info("Loading Nuclei data")
        nuclei_df = pd.read_json(NUCLEI_JSON, lines=True)
        nuclei_df.rename(columns={"ID": "cve"}, inplace=True)
        nuclei_df = nuclei_df.drop(columns=['Info', 'file_path'])
        nuclei_df['nuclei'] = True
    except Exception as e:
        logger.error(f"Failed to load Nuclei data: {e}")
        nuclei_df = pd.DataFrame(columns=['cve', 'nuclei'])
        metrics['failed_sources']['nuclei'] = str(e)

    try:
        #Load Poc-in-GitHub
        logger.info("Loading GitHub PoC data")
        poc_github_df = pd.DataFrame(extract_cves_from_github(POC_GITHUB), columns=['cve'])
        poc_github_df['poc_github'] = True
    except Exception as e:
        logger.error(f"Failed to load GitHub PoC data: {e}")
        poc_github_df = pd.DataFrame(columns=['cve', 'poc_github'])
        metrics['failed_sources']['poc_github'] = str(e)

    # Merge all dataframes with error handling
    try:
        logger.info('Mapping EPSS Data')
        df = pd.merge(df, epss_df, on='cve', how='left')

        logger.info('Mapping KEV Data')
        df = pd.merge(df, kev_df, on='cve', how='left')
        
        logger.info('Mapping VulnCheck KEV Data')
        df = pd.merge(df, vulncheck_kev_df, on='cve', how='left')

        logger.info('Mapping ExploitDB Data')
        df = pd.merge(df, exploitdb_df, on='cve', how='left')

        logger.info('Mapping Metasploit Data')
        df = pd.merge(df, metasploit_df, on='cve', how='left')
        
        # Map Metasploit quality data if available
        if not metasploit_quality_df.empty:
            logger.info('Mapping Metasploit Quality Data')
            df = pd.merge(df, metasploit_quality_df, on='cve', how='left')

        logger.info('Mapping Nuclei Data')
        df = pd.merge(df, nuclei_df, on='cve', how='left')

        logger.info('Mapping GitHub PoC Data')
        df = pd.merge(df, poc_github_df, on='cve', how='left')

        df = df.drop_duplicates(subset='cve')
        
        # Fill NaN values with appropriate defaults
        bool_columns = ['cisa_kev', 'vulncheck_kev', 'exploitdb', 'metasploit', 'nuclei', 'poc_github']
        df[bool_columns] = df[bool_columns].fillna(False)
        
        # Fill NaN values in quality metrics columns
        if 'metasploit_reliability' in df.columns:
            df['metasploit_reliability'] = df['metasploit_reliability'].fillna(0.0)
        if 'metasploit_rank' in df.columns:
            df['metasploit_rank'] = df['metasploit_rank'].fillna(0.0)
            
        metrics['successful_enrichments'] = len(df)
        logger.info(f"Successfully enriched {metrics['successful_enrichments']} CVEs")
        
    except Exception as e:
        logger.error(f"Error during data merging: {e}")
        # Return original dataframe if merging fails
        metrics['failed_sources']['data_merging'] = str(e)
        
    return df


def extract_cves_from_github(url):
    response = safe_request(url)
    if response.status_code == 200:
        content = response.text
    else:
        logger.error(f"Failed to fetch GitHub PoC data: HTTP {response.status_code}")
        content = ""

    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_matches = re.findall(cve_pattern, content)
    unique_cves = set(cve_matches)
    return list(unique_cves)


def get_vulncheck_data():
    if not VULNCHECK_API_KEY:
        logger.warning("VULNCHECK_API_KEY not found in environment variables")
        return []
        
    data = []
    headers = {
      "accept": "application/json",
      "authorization": f"Bearer {VULNCHECK_API_KEY}"
    }
    
    try:
        response = safe_request(VULNCHECK_KEV, headers=headers)
        response_json = response.json()
        
        # Validate response format
        if '_meta' not in response_json or 'data' not in response_json:
            logger.error("Unexpected VulnCheck API response format")
            return []
            
        current_page = response_json.get('_meta', {}).get('page', 1)
        total_pages = response_json.get('_meta', {}).get('total_pages', 1)
        data.extend(response_json.get('data', []))
        
        while current_page < total_pages:
            current_page += 1
            next_page_response = safe_request(f"{VULNCHECK_KEV}?page={current_page}", headers=headers)
            next_page_json = next_page_response.json()
            
            if 'data' in next_page_json:
                data.extend(next_page_json.get('data', []))
            else:
                logger.warning(f"Missing data in VulnCheck API response for page {current_page}")
                
    except Exception as e:
        logger.error(f"Error fetching VulnCheck data: {e}")
        
    return data


def map_reliability_to_score(reliability_text):
    """
    Map Metasploit reliability text to numerical score
    """
    reliability_map = {
        'Excellent': 1.0,
        'Great': 0.9,
        'Good': 0.8,
        'Normal': 0.7,
        'Average': 0.6,
        'Low': 0.4,
        'Manual': 0.3,
        'Unknown': 0.5  # Default for unknown values
    }
    return reliability_map.get(reliability_text, 0.5)


def map_rank_to_score(rank_text):
    """
    Map Metasploit rank text to numerical score
    """
    rank_map = {
        'Excellent': 1.0,
        'Great': 0.9,
        'Good': 0.8,
        'Normal': 0.7,
        'Average': 0.6,
        'Low': 0.4,
        'Manual': 0.3,
        'Unknown': 0.5  # Default for unknown values
    }
    return rank_map.get(rank_text, 0.5)


def evaluate_exploit_quality(row):
    """
    Evaluate the quality of available exploits based on reliability, ease of use,
    and effectiveness.
    
    Returns a dict with quality metrics and an overall quality score.
    """
    quality_score = 0
    reliability = 0
    ease_of_use = 0
    effectiveness = 0
    
    # Count how many sources have exploits
    exploit_sources = 0
    
    # Calculate metrics based on available exploit sources
    for source, metrics in SOURCE_QUALITY.items():
        if source in row and row[source]:
            exploit_sources += 1
            reliability += metrics['reliability']
            ease_of_use += metrics['ease']
            effectiveness += metrics['effectiveness']
            
    # Include Metasploit quality data if available
    if 'metasploit' in row and row['metasploit'] and 'metasploit_reliability' in row:
        # Replace the default metasploit reliability with the actual value from the module
        reliability = reliability - SOURCE_QUALITY['metasploit']['reliability'] + row['metasploit_reliability']
    
    # Normalize if we have exploit sources
    if exploit_sources > 0:
        reliability /= exploit_sources
        ease_of_use /= exploit_sources
        effectiveness /= exploit_sources
        
        # Calculate overall quality score (weighted average)
        quality_score = (reliability * 0.4) + (ease_of_use * 0.3) + (effectiveness * 0.3)
    
    return {
        'reliability': round(reliability, 2),
        'ease_of_use': round(ease_of_use, 2),
        'effectiveness': round(effectiveness, 2),
        'quality_score': round(quality_score, 2),
        'exploit_sources': exploit_sources
    }


def normalize_version(ver):
    """
    Normalize version string for consistent comparison
    """
    if pd.isna(ver) or ver == 'N/A':
        return 'N/A'
    
    try:
        # Convert to string and handle different formats
        ver_str = str(ver).strip()
        
        # Check for CVSS 4.0
        if '4' in ver_str:
            return '4.0'
        # Check for CVSS 3.1
        elif '3.1' in ver_str:
            return '3.1'
        # Check for CVSS 3.0
        elif '3.0' in ver_str or '3' in ver_str:
            return '3.0'
        # Check for CVSS 2.0
        elif '2' in ver_str:
            return '2.0'
        else:
            return ver_str
    except Exception as e:
        logger.warning(f"Error normalizing version {ver}: {e}")
        return str(ver)


def determine_exploit_maturity(row):
    """
    Determine exploit maturity using a clear prioritized decision tree
    with proper version-specific values according to CVSS standards
    """
    cvss_version = normalize_version(row['cvss_version'])
    
    # Include quality assessment in decision making
    quality_data = row.get('quality_data', {})
    quality_score = quality_data.get('quality_score', 0)
    exploit_sources = quality_data.get('exploit_sources', 0)
    
    # Get appropriate metrics for this CVSS version
    version_metrics = CVSS_VERSION_METRICS.get(cvss_version, CVSS_VERSION_METRICS.get('3.1', {}))
    exploit_metrics = version_metrics.get('exploit_maturity', {})
    
    # Highest priority: Known exploited vulnerabilities or high EPSS score
    if row['cisa_kev'] or row['vulncheck_kev'] or (not pd.isna(row['epss']) and row['epss'] >= EPSS_THRESHOLD):
        if cvss_version == '4.0':
            return exploit_metrics.get('attacked', 'E:A')  # CVSS 4.0: Attacked 
        else:
            return exploit_metrics.get('high', 'E:H')  # CVSS 2.0/3.0/3.1: High
    
    # Second priority: Functional exploits (Metasploit frameworks or Nuclei templates)
    if row['metasploit'] or row['nuclei']:
        if cvss_version == '4.0':
            return exploit_metrics.get('attacked', 'E:A')  # CVSS 4.0: Attacked
        elif quality_score >= 0.8:  # High quality exploit
            return exploit_metrics.get('high', 'E:H')  # CVSS 3.0/3.1: High
        else:
            return exploit_metrics.get('functional', 'E:F')  # CVSS 3.0/3.1: Functional
    
    # Third priority: Proof of concept exploits
    if row['exploitdb'] or row['poc_github']:
        if cvss_version == '2.0':
            return exploit_metrics.get('poc', 'E:POC')  # CVSS 2.0: POC
        elif cvss_version == '4.0':
            return exploit_metrics.get('poc', 'E:P')  # CVSS 4.0: P
        elif quality_score >= 0.8 and exploit_sources >= 2:
            return exploit_metrics.get('functional', 'E:F')  # Upgraded to Functional due to high quality
        else:
            return exploit_metrics.get('poc', 'E:P')  # CVSS 3.0/3.1: P
    
    # Default: Unknown or Unreported exploit maturity
    if cvss_version == '4.0':
        return exploit_metrics.get('unreported', 'E:U')  # Note: this is "Unreported" in 4.0
    else:
        return exploit_metrics.get('unproven', 'E:U')  # "Unproven" in 2.0/3.0/3.1


def update_vector_with_maturity(base_vector, exploit_maturity):
    """
    Update CVSS vector string with exploit maturity in a more robust way
    """
    if base_vector == 'N/A':
        return base_vector
        
    # Check if vector already has an exploit maturity component
    if '/E:' in base_vector:
        # Replace existing exploit maturity
        parts = base_vector.split('/')
        new_parts = []
        for part in parts:
            if part.startswith('E:'):
                new_parts.append(exploit_maturity)
            else:
                new_parts.append(part)
        return '/'.join(new_parts)
    else:
        # Add exploit maturity component
        return f"{base_vector}/{exploit_maturity}"


def complete_temporal_vector(base_vector, exploit_maturity, cvss_version):
    """
    Complete the temporal vector with default values for missing temporal metrics
    based on CVSS version-specific requirements
    """
    if base_vector == 'N/A':
        return base_vector
        
    # Normalize CVSS version
    cvss_version = normalize_version(cvss_version)
    
    # Get the appropriate metrics for this version
    version_metrics = CVSS_VERSION_METRICS.get(cvss_version, CVSS_VERSION_METRICS.get('3.1', {}))
    
    # Extract the exploit maturity value (after the colon)
    e_value = exploit_maturity.split(':')[1]
    
    # Handle CVSS 4.0 differently - in 4.0, E is part of the Threat metrics group
    if cvss_version == '4.0':
        # In CVSS 4.0, we simply update the Exploit Maturity value without adding other metrics
        if 'CVSS:4.0' in base_vector:
            if '/E:' not in base_vector:  # Temporal metrics not yet included
                return update_vector_with_maturity(base_vector, exploit_maturity)
            else:
                return update_vector_with_maturity(base_vector, exploit_maturity)
        else:
            logger.warning(f"Invalid CVSS 4.0 vector format: {base_vector}")
            return base_vector
            
    elif cvss_version in ['3.0', '3.1']:
        # CVSS 3.0/3.1 temporal metrics
        default_temporal = {
            'E': e_value,     # Exploit Code Maturity (from our analysis)
            'RL': version_metrics.get('remediation', {}).get('official', 'O'),
            'RC': version_metrics.get('confidence', {}).get('confirmed', 'C')
        }
        
        # Check for existing temporal metrics and remove them
        parts = base_vector.split('/')
        base_parts = [part for part in parts if not (part.startswith('E:') or part.startswith('RL:') or part.startswith('RC:'))]
        
        # Add updated temporal metrics
        for key, value in default_temporal.items():
            base_parts.append(f"{key}:{value}")
        
        return '/'.join(base_parts)
    
    elif cvss_version == '2.0':
        # CVSS 2.0 temporal metrics
        default_temporal = {
            'E': e_value,     # Exploitability (from our analysis)
            'RL': version_metrics.get('remediation', {}).get('official', 'OF'),
            'RC': version_metrics.get('confidence', {}).get('confirmed', 'C')
        }
        
        # Check for existing temporal metrics and remove them
        parts = base_vector.split('/')
        base_parts = [part for part in parts if not (part.startswith('E:') or part.startswith('RL:') or part.startswith('RC:'))]
        
        # Add updated temporal metrics
        for key, value in default_temporal.items():
            base_parts.append(f"{key}:{value}")
        
        return '/'.join(base_parts)
    
    # For unrecognized versions, just add exploit maturity
    return update_vector_with_maturity(base_vector, exploit_maturity)

def validate_cvss_vector(vector, version):
    """
    Validate the CVSS vector string according to standards
    """
    if not vector or vector == 'N/A':
        return False
        
    # Basic patterns for different CVSS versions
    patterns = {
        '2.0': r'^AV:[LAN]/AC:[HML]/Au:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]',
        '3.0': r'^CVSS:3\.0/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]',
        '3.1': r'^CVSS:3\.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]',
        '4.0': r'^CVSS:4\.0/AV:[NALP]/AC:[LH]/AT:[NP]/PR:[NLH]/UI:[NPA]/VC:[HLN]/VI:[HLN]/VA:[HLN]/SC:[HLN]/SI:[HLN]/SA:[HLN]'
    }
    
    if version in patterns:
        pattern = patterns[version]
        if re.match(pattern, vector):
            return True
        else:
            logger.warning(f"Vector {vector} does not match pattern for CVSS {version}")
            return False
    else:
        logger.warning(f"Unknown CVSS version: {version}")
        return False


def compute_cvss(row):
    """
    Compute CVSS score based on vector string and version
    """
    try:
        cvss_version = normalize_version(row['cvss_version'])
        cvss_vector = row['cvss-bt_vector']
        
        if cvss_version == 'N/A' or pd.isna(cvss_version):
            return 'UNKNOWN', 'UNKNOWN'
            
        elif cvss_version == '4.0':
            try:
                c = cvss.CVSS4(cvss_vector)
                # For CVSS 4.0, get the BT (Base+Threat) score 
                score = c.scores()[1]  # Index 1 contains BT score
                return round(score, 1), str(c.severities()[1]).upper()
            except Exception as e:
                logger.error(f"Error computing CVSS 4.0 score for {row['cve']}: {e}")
                return 'UNKNOWN', 'UNKNOWN'
            
        elif cvss_version in ['3.0', '3.1']:
            # Handle both CVSS 3.0 and 3.1
            c = cvss.CVSS3(cvss_vector)
            return c.temporal_score, str(c.severities()[1]).upper()
            
        elif cvss_version == '2.0':
            c = cvss.CVSS2(cvss_vector)
            return c.temporal_score, str(c.severities()[1]).upper()
            
        else:
            logger.warning(f"Unknown CVSS version: {cvss_version}")
            return 'UNKNOWN', 'UNKNOWN'
            
    except Exception as e:
        logger.error(f"Error computing CVSS for {row['cve']}: {e}")
        logger.error(f"Vector: {row.get('cvss-bt_vector', 'N/A')}, Version: {row.get('cvss_version', 'N/A')}")
        return 'UNKNOWN', 'UNKNOWN'


def calculate_cvss_te_score(row):
    """
    Calculate the CVSS-TE (Threat-Enhanced) score that incorporates:
    1. Standard CVSS Base+Temporal score
    2. Exploit quality metrics
    3. Threat intelligence context
    """
    # Start with the CVSS-BT score if available
    try:
        base_score = float(row['cvss-bt_score']) if row['cvss-bt_score'] != 'UNKNOWN' else None
    except (ValueError, TypeError):
        base_score = None
    
    if base_score is None:
        return 'UNKNOWN'
    
    # Get quality metrics
    quality_score = row['quality_score']
    exploit_sources = row['exploit_sources']
    
    # Calculate a quality multiplier (0.8-1.2 range)
    # Higher quality exploits increase the effective risk
    quality_multiplier = 1.0
    if exploit_sources > 0:
        # Scale from 0.8 (poor quality) to 1.2 (excellent quality)
        quality_multiplier = 0.8 + (quality_score * 0.4)
    
    # Calculate a threat intelligence factor (0-2 points)
    threat_intel_factor = 0.0
    
    # KEV adds significant weight
    if row['cisa_kev'] or row['vulncheck_kev']:
        threat_intel_factor += 1.0
    
    # High EPSS adds moderate weight
    if not pd.isna(row['epss']) and row['epss'] >= 0.5:  # Higher threshold for TE
        threat_intel_factor += 0.5
    elif not pd.isna(row['epss']) and row['epss'] >= EPSS_THRESHOLD:
        threat_intel_factor += 0.25
    
    # Multiple exploit sources indicate broader threat landscape
    if exploit_sources >= 3:
        threat_intel_factor += 0.5
    elif exploit_sources >= 2:
        threat_intel_factor += 0.25
    
    # Calculate final CVSS-TE score
    # Formula: Min(10, Base_Temporal_Score * Quality_Multiplier + Threat_Intel_Factor)
    te_score = min(10.0, base_score * quality_multiplier + threat_intel_factor)
    
    # Round to one decimal place
    te_score = round(te_score, 1)
    
    return te_score


def get_te_severity(score):
    """
    Determine TE severity based on score
    """
    if score == 'UNKNOWN':
        return 'UNKNOWN'
    try:
        score_float = float(score)
        if score_float >= 9.0:
            return 'CRITICAL'
        elif score_float >= 7.0:
            return 'HIGH'
        elif score_float >= 4.0:
            return 'MEDIUM'
        elif score_float >= 0.1:
            return 'LOW'
        else:
            return 'NONE'
    except (ValueError, TypeError):
        return 'UNKNOWN'


def update_temporal_score(df, epss_threshold):
    """
    Update temporal score and severity based on exploit maturity
    """
    logger.info("Beginning temporal score update")
    
    # Set default exploit maturity
    df['exploit_maturity'] = 'E:U'  # Default value
    
    # Evaluate exploit quality for each CVE
    logger.info("Evaluating exploit quality metrics")
    quality_metrics = df.apply(evaluate_exploit_quality, axis=1, result_type='expand')
    
    # Add quality metrics to the dataframe
    for col in ['reliability', 'ease_of_use', 'effectiveness', 'quality_score', 'exploit_sources']:
        df[col] = quality_metrics[col]
    
    # Store quality data as a dictionary for use in determine_exploit_maturity
    df['quality_data'] = df.apply(
        lambda row: {
            'quality_score': row['quality_score'], 
            'exploit_sources': row['exploit_sources'],
            'reliability': row['reliability'],
            'ease_of_use': row['ease_of_use'],
            'effectiveness': row['effectiveness']
        }, 
        axis=1
    )
    
    # Determine exploit maturity using the standards-compliant approach
    logger.info("Determining exploit maturity")
    df['exploit_maturity'] = df.apply(determine_exploit_maturity, axis=1)
    
    # Update vector with complete temporal metrics
    logger.info("Updating CVSS vectors with complete temporal metrics")
    df['cvss-bt_vector'] = df.apply(
        lambda row: complete_temporal_vector(
            row['base_vector'], 
            row['exploit_maturity'], 
            row['cvss_version']
        ), 
        axis=1
    )

    # Apply CVSS computation
    logger.info('Computing CVSS-BT scores and severities')
    errors = 0
    for index, row in df.iterrows():
        try:
            score, severity = compute_cvss(row)
            df.at[index, 'cvss-bt_score'] = score
            df.at[index, 'cvss-bt_severity'] = severity
        except Exception as e:
            errors += 1
            logger.error(f"Error computing CVSS for CVE {row.get('cve', 'unknown')}: {e}")
            df.at[index, 'cvss-bt_score'] = 'UNKNOWN'
            df.at[index, 'cvss-bt_severity'] = 'UNKNOWN'
    
    if errors > 0:
        logger.warning(f"Encountered {errors} errors when computing CVSS scores")
    
    # Calculate CVSS-TE scores without explanations
    logger.info('Computing CVSS-TE scores')
    df['cvss-te_score'] = df.apply(calculate_cvss_te_score, axis=1)
    
    # Determine TE severity based on score
    df['cvss-te_severity'] = df['cvss-te_score'].apply(get_te_severity)

    return df