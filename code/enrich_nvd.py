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
    """
    Extract CVE IDs from GitHub PoC repository
    """
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
    """
    Get vulnerability data from VulnCheck API
    """
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
    
    Now uses a weighted approach that emphasizes the highest quality exploit
    to prevent dilution of high-quality exploits by lower-quality ones.
    """
    # Initialize metrics
    quality_score = 0
    reliability_scores = []
    ease_of_use_scores = []
    effectiveness_scores = []
    
    # Count how many sources have exploits
    exploit_sources = 0
    
    # Calculate metrics based on available exploit sources
    for source, metrics in SOURCE_QUALITY.items():
        if source in row and row[source]:
            exploit_sources += 1
            reliability_scores.append(metrics['reliability'])
            ease_of_use_scores.append(metrics['ease'])
            effectiveness_scores.append(metrics['effectiveness'])
            
    # Include Metasploit quality data if available
    if 'metasploit' in row and row['metasploit'] and 'metasploit_reliability' in row:
        # Replace the default metasploit reliability with the actual value from the module
        metasploit_index = next((i for i, s in enumerate(reliability_scores) 
                                if s == SOURCE_QUALITY['metasploit']['reliability']), None)
        if metasploit_index is not None:
            reliability_scores[metasploit_index] = row['metasploit_reliability']
    
    # Calculate weighted quality metrics if we have exploit sources
    if exploit_sources > 0:
        # Find maximum values for each metric
        max_reliability = max(reliability_scores) if reliability_scores else 0
        max_ease = max(ease_of_use_scores) if ease_of_use_scores else 0
        max_effectiveness = max(effectiveness_scores) if effectiveness_scores else 0
        
        # Calculate averages of remaining values (excluding max)
        avg_reliability = (sum(reliability_scores) - max_reliability) / (len(reliability_scores) - 1) if len(reliability_scores) > 1 else max_reliability
        avg_ease = (sum(ease_of_use_scores) - max_ease) / (len(ease_of_use_scores) - 1) if len(ease_of_use_scores) > 1 else max_ease
        avg_effectiveness = (sum(effectiveness_scores) - max_effectiveness) / (len(effectiveness_scores) - 1) if len(effectiveness_scores) > 1 else max_effectiveness
        
        # Apply weighted approach: 70% weight to best score, 30% to average of remaining
        weighted_reliability = (0.7 * max_reliability) + (0.3 * avg_reliability)
        weighted_ease = (0.7 * max_ease) + (0.3 * avg_ease)
        weighted_effectiveness = (0.7 * max_effectiveness) + (0.3 * avg_effectiveness)
        
        # Calculate overall quality score (weighted average)
        quality_score = (weighted_reliability * 0.4) + (weighted_ease * 0.3) + (weighted_effectiveness * 0.3)
    
    return {
        'reliability': round(max(reliability_scores) if reliability_scores else 0, 2),
        'ease_of_use': round(max(ease_of_use_scores) if ease_of_use_scores else 0, 2),
        'effectiveness': round(max(effectiveness_scores) if effectiveness_scores else 0, 2),
        'quality_score': round(quality_score, 2),
        'exploit_sources': exploit_sources
    }


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
    
    # Define conditions for exploit maturity determination using vectorized operations
    # For CVSS 4.0 "Attacked" condition
    condition_ea = (df['cisa_kev']) | (df['epss'] >= epss_threshold) | (df['vulncheck_kev']) | (df['metasploit'])
    
    # For CVSS 2.0/3.0/3.1 "High" condition
    condition_eh = (df['cisa_kev']) | (df['epss'] >= epss_threshold) | (df['vulncheck_kev'])
    
    # For CVSS 2.0/3.0/3.1 "Functional" condition
    condition_ef = (~condition_eh) & ((df['nuclei']) | (df['metasploit']))
    
    # For CVSS 2.0/3.0/3.1 "Proof-of-Concept" condition
    condition_ep = (~condition_eh) & (~condition_ef) & (df['exploitdb'] | df['poc_github'])
    
    # For CVSS 4.0 "Proof-of-Concept" condition
    condition_ep4 = (~condition_ea) & ((df['nuclei']) | (df['exploitdb'] | df['poc_github']))
    
    # Apply conditions to assign exploit maturity values
    df.loc[condition_eh & (df['cvss_version'].astype(str) != '4.0'), 'exploit_maturity'] = 'E:H'
    df.loc[condition_ea & (df['cvss_version'].astype(str) == '4.0'), 'exploit_maturity'] = 'E:A'
    df.loc[condition_ef & (df['cvss_version'].astype(str) != '4.0'), 'exploit_maturity'] = 'E:F'
    df.loc[condition_ep & (df['cvss_version'].astype(str) == '2.0'), 'exploit_maturity'] = 'E:POC'
    df.loc[condition_ep & (df['cvss_version'].astype(str) != '2.0') & (df['cvss_version'].astype(str) != '4.0'), 'exploit_maturity'] = 'E:P'
    df.loc[condition_ep4 & (df['cvss_version'].astype(str) == '4.0'), 'exploit_maturity'] = 'E:P'
    
    logger.info("Exploit maturity determined")
    
    # Update vector with exploit maturity
    logger.info("Updating CVSS vectors with temporal metrics")
    df['cvss-bt_vector'] = df.apply(
        lambda row: update_vector_string(row['base_vector'], row['exploit_maturity']), 
        axis=1
    )

    # Apply CVSS computation
    logger.info('Computing CVSS-BT scores and severities')
    df[['cvss-bt_score', 'cvss-bt_severity']] = df.apply(
        compute_cvss, 
        axis=1, 
        result_type='expand'
    )
    
    # Calculate CVSS-TE scores
    logger.info('Computing CVSS-TE scores')
    df['cvss-te_score'] = df.apply(calculate_cvss_te_score, axis=1)
    
    # Determine TE severity based on score
    df['cvss-te_severity'] = df['cvss-te_score'].apply(get_te_severity)
    
    # Count successful calculations
    bt_unknown = len(df[df['cvss-bt_score'] == 'UNKNOWN'])
    te_unknown = len(df[df['cvss-te_score'] == 'UNKNOWN'])
    logger.info(f"Completed with {bt_unknown} unknown BT scores and {te_unknown} unknown TE scores")

    return df


def update_vector_string(base_vector, exploit_maturity):
    """
    Update CVSS vector string with exploit maturity
    """
    if base_vector == 'N/A' or pd.isna(base_vector):
        return base_vector
        
    # Replace existing E:X with new exploit maturity
    if '/E:' in base_vector:
        parts = base_vector.split('/')
        new_parts = []
        for part in parts:
            if part.startswith('E:'):
                new_parts.append(exploit_maturity)
            else:
                new_parts.append(part)
        return '/'.join(new_parts)
    else:
        # Just append the exploit maturity
        return f"{base_vector}/{exploit_maturity}"


def compute_cvss(row):
    """
    Compute CVSS score based on vector string and version
    """
    try:
        cvss_version = str(row.get('cvss_version', ''))
        vector = row.get('cvss-bt_vector', '')
        cve_id = row.get('cve', 'unknown')
        
        if pd.isna(vector) or vector == 'N/A' or pd.isna(cvss_version) or 'N/A' in cvss_version:
            return 'UNKNOWN', 'UNKNOWN'
            
        if '4' in cvss_version:
            try:
                c = cvss.CVSS4(vector)
                # For CVSS 4.0, get the BT (Base+Threat) score
                scores_tuple = c.scores()
                severities_tuple = c.severities()
                
                # Handle different possible return formats
                if isinstance(scores_tuple, tuple) and len(scores_tuple) > 1:
                    score = scores_tuple[1]  # BT score at index 1
                    severity = str(severities_tuple[1]).upper() if len(severities_tuple) > 1 else 'UNKNOWN'
                elif isinstance(scores_tuple, (int, float)):
                    score = scores_tuple
                    severity = str(severities_tuple).upper() if severities_tuple else 'UNKNOWN'
                else:
                    # Try base score as fallback
                    score = c.base_score if hasattr(c, 'base_score') else scores_tuple[0]
                    severity = str(severities_tuple[0]).upper() if severities_tuple else 'UNKNOWN'
                
                return round(float(score), 1), severity
            except Exception as e:
                logger.warning(f"Error computing CVSS 4.0 score for {cve_id}: {e}")
                return 'UNKNOWN', 'UNKNOWN'
            
        elif '3' in cvss_version:
            try:
                c = cvss.CVSS3(vector)
                return c.temporal_score, str(c.severities()[1]).upper()
            except Exception as e:
                logger.warning(f"Error computing CVSS 3.x score for {cve_id}: {e}")
                return 'UNKNOWN', 'UNKNOWN'
            
        elif '2' in cvss_version:
            try:
                c = cvss.CVSS2(vector)
                return c.temporal_score, str(c.severities()[1]).upper()
            except Exception as e:
                logger.warning(f"Error computing CVSS 2.0 score for {cve_id}: {e}")
                return 'UNKNOWN', 'UNKNOWN'
            
        else:
            logger.warning(f"Unknown CVSS version for {cve_id}: {cvss_version}")
            return 'UNKNOWN', 'UNKNOWN'
            
    except Exception as e:
        logger.warning(f"General error computing CVSS for {row.get('cve', 'unknown')}: {e}")
        return 'UNKNOWN', 'UNKNOWN'

def calculate_cvss_te_score(row):
    """
    Calculate CVSS-TE score incorporating threat intelligence factors
    with refined handling of exploit quality, unexploited vulnerabilities,
    and more granular exploit source counting.
    """
    # Start with the CVSS-BT score
    try:
        bt_score = row.get('cvss-bt_score')
        if pd.isna(bt_score) or bt_score == 'UNKNOWN':
            return 'UNKNOWN'
        base_score = float(bt_score)
    except (ValueError, TypeError):
        return 'UNKNOWN'
    
    # Get quality score and exploit sources
    quality_score = row.get('quality_score', 0)
    exploit_sources = row.get('exploit_sources', 0)
    
    # Calculate a quality multiplier (0.8-1.2 range)
    if exploit_sources > 0:
        # Scale from 0.8 (poor quality) to 1.2 (excellent quality)
        quality_multiplier = 0.8 + (quality_score * 0.4)
    else:
        # Handle unexploited vulnerabilities
        epss = row.get('epss', 0)
        if epss is not None and not pd.isna(epss) and epss < EPSS_THRESHOLD:
            # Slight penalty for vulnerabilities with no exploits and low EPSS
            quality_multiplier = 0.95
        else:
            # Default for unexploited but high EPSS
            quality_multiplier = 1.0
    
    # Calculate a threat intelligence factor (0-2 points)
    threat_intel_factor = 0.0
    
    # KEV presence - prioritize CISA KEV, only use VulnCheck if not in CISA
    kev_boost = 0.0
    if row.get('cisa_kev', False):
        kev_boost = 1.0
    elif row.get('vulncheck_kev', False):
        kev_boost = 0.8
    
    # EPSS boost with anti-stacking logic when KEV is present
    epss_boost = 0.0
    epss = row.get('epss', 0)
    if epss is not None and not pd.isna(epss):
        if epss >= 0.5:  # Higher threshold for TE
            epss_boost = 0.5
        elif epss >= EPSS_THRESHOLD:
            epss_boost = 0.25
    
    # Avoid over-stacking EPSS and KEV boosts
    if kev_boost > 0 and epss_boost > 0:
        # Use the higher of the two boosts
        threat_intel_factor += max(kev_boost, epss_boost)
    else:
        # Add both if only one is present
        threat_intel_factor += kev_boost + epss_boost
    
    # Granular exploit source counting
    exploit_source_boost = 0.0
    if exploit_sources == 2:
        exploit_source_boost = 0.25
    elif exploit_sources in [3, 4]:
        exploit_source_boost = 0.5
    elif exploit_sources >= 5:
        exploit_source_boost = 0.75
    
    threat_intel_factor += exploit_source_boost
    
    # Time-based decay factor for older vulnerabilities
    time_decay = 0.0
    try:
        # Only apply if published_date is available
        published_date = row.get('published_date')
        if published_date and not pd.isna(published_date):
            from datetime import datetime
            
            # Parse date string to datetime
            if isinstance(published_date, str):
                pub_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%M:%S.%f')
            else:
                pub_date = published_date
                
            # Calculate years since publication
            current_time = datetime.now()
            years_since_pub = (current_time - pub_date).days / 365.25
            
            # Apply decay for older vulnerabilities with no exploitation evidence
            if years_since_pub > 5 and exploit_sources == 0 and not row.get('cisa_kev', False) and not row.get('vulncheck_kev', False):
                time_decay = min(0.2, (years_since_pub - 5) * 0.04)  # Max 0.2 reduction for very old vulnerabilities
    except (ValueError, TypeError, AttributeError) as e:
        # Skip time decay if there's any issue with date parsing
        logging.debug(f"Could not apply time decay for {row.get('cve', 'unknown')}: {e}")
    
    # Calculate final CVSS-TE score
    # Formula: Min(10, Base_Temporal_Score * Quality_Multiplier + Threat_Intel_Factor - Time_Decay)
    te_score = min(10.0, (base_score * quality_multiplier) + threat_intel_factor - time_decay)
    
    # Round to one decimal place
    return round(te_score, 1)

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


def debug_cvss_calculation(cve_id, df):
    """
    Debug helper function to inspect CVSS calculation for a specific CVE
    """
    if cve_id not in df['cve'].values:
        return f"CVE {cve_id} not found in dataset"
    
    # Get the row for this CVE
    cve_row = df[df['cve'] == cve_id].iloc[0]
    
    # Extract all relevant data
    debug_info = {
        "cve": cve_id,
        "cvss_version": cve_row.get('cvss_version'),
        "base_score": cve_row.get('base_score'),
        "base_severity": cve_row.get('base_severity'),
        "base_vector": cve_row.get('base_vector'),
        
        "exploit_sources": {
            "cisa_kev": bool(cve_row.get('cisa_kev', False)),
            "vulncheck_kev": bool(cve_row.get('vulncheck_kev', False)),
            "exploitdb": bool(cve_row.get('exploitdb', False)),
            "metasploit": bool(cve_row.get('metasploit', False)),
            "nuclei": bool(cve_row.get('nuclei', False)),
            "poc_github": bool(cve_row.get('poc_github', False)),
            "epss": cve_row.get('epss')
        },
        
        "quality_metrics": {
            "reliability": cve_row.get('reliability'),
            "ease_of_use": cve_row.get('ease_of_use'),
            "effectiveness": cve_row.get('effectiveness'),
            "quality_score": cve_row.get('quality_score'),
            "exploit_sources": cve_row.get('exploit_sources')
        },
        
        "temporal_info": {
            "exploit_maturity": cve_row.get('exploit_maturity'),
            "cvss-bt_vector": cve_row.get('cvss-bt_vector'),
            "cvss-bt_score": cve_row.get('cvss-bt_score'),
            "cvss-bt_severity": cve_row.get('cvss-bt_severity'),
        },
        
        "te_info": {
            "cvss-te_score": cve_row.get('cvss-te_score'),
            "cvss-te_severity": cve_row.get('cvss-te_severity'),
        }
    }
    
    # Test manual calculation
    test_bt_vector = update_vector_string(cve_row['base_vector'], cve_row['exploit_maturity'])
    test_bt_score, test_bt_severity = compute_cvss(cve_row)
    
    debug_info["test_calculation"] = {
        "test_bt_vector": test_bt_vector,
        "test_bt_score": test_bt_score,
        "test_bt_severity": test_bt_severity,
        "vector_match": test_bt_vector == cve_row.get('cvss-bt_vector'),
        "score_match": test_bt_score == cve_row.get('cvss-bt_score')
    }
    
    return debug_info


def recalculate_problem_cves(df):
    """
    Identify and recalculate CVEs with unknown or inconsistent scores.
    Useful for debugging and fixing data issues.
    """
    # Find CVEs with unknown scores
    problem_cves = df[(df['cvss-bt_score'] == 'UNKNOWN') | (df['cvss-te_score'] == 'UNKNOWN')]
    problem_count = len(problem_cves)
    
    if problem_count == 0:
        logger.info("No problem CVEs found")
        return df
    
    logger.info(f"Found {problem_count} CVEs with unknown scores")
    
    # Process each problem CVE individually
    for idx, row in problem_cves.iterrows():
        cve_id = row['cve']
        logger.info(f"Recalculating {cve_id}")
        
        try:
            # Update vector string
            vector = update_vector_string(row['base_vector'], row['exploit_maturity'])
            df.at[idx, 'cvss-bt_vector'] = vector
            
            # Recalculate BT score
            bt_score, bt_severity = compute_cvss(row)
            df.at[idx, 'cvss-bt_score'] = bt_score
            df.at[idx, 'cvss-bt_severity'] = bt_severity
            
            # Recalculate TE score
            if bt_score != 'UNKNOWN':
                # Create a modified row with the updated BT score
                mod_row = row.copy()
                mod_row['cvss-bt_score'] = bt_score
                te_score = calculate_cvss_te_score(mod_row)
                df.at[idx, 'cvss-te_score'] = te_score
                df.at[idx, 'cvss-te_severity'] = get_te_severity(te_score)
                
                logger.info(f"  Fixed {cve_id}: BT={bt_score}, TE={te_score}")
            else:
                logger.warning(f"  Unable to fix {cve_id}: BT score still unknown")
                
        except Exception as e:
            logger.error(f"  Error recalculating {cve_id}: {e}")
    
    # Count remaining problems
    remaining = len(df[(df['cvss-bt_score'] == 'UNKNOWN') | (df['cvss-te_score'] == 'UNKNOWN')])
    logger.info(f"Recalculation complete. Remaining problems: {remaining}")
    
    return df