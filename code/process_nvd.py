from datetime import datetime, date, timezone
from pathlib import Path
import pandas as pd
import logging
import json
import requests
import gzip
import os
import sys
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Import the enrichment module
try:
    import enrich_nvd
except ImportError:
    logger.error("Could not import enrich module. Make sure enrich_nvd.py is in the same directory.")
    sys.exit(1)

# Constants
EPSS_CSV = f'https://epss.cyentia.com/epss_scores-current.csv.gz'
EPSS_BACKUP = './data/epss/epss_scores.csv'  # Backup location
TIMESTAMP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'last_run.txt')

def create_directories():
    """Create necessary directories for the script"""
    os.makedirs('./data/epss', exist_ok=True)

def generate_nvd_feeds():
    """Generate a dictionary of all NVD feeds from 2002 to present year"""
    feeds = {
        'recent': 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz',
        'modified': 'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz',
    }
    
    current_year = date.today().year
    for year in range(2002, current_year + 1):
        feeds[str(year)] = f'https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz'
    
    return feeds

NVD_FEEDS = generate_nvd_feeds()

def download_nvd_feeds(max_retries=3, retry_delay=5):
    """
    Download NVD feeds, decompress them, and save to the current directory.
    
    Returns:
        list: List of downloaded JSON filenames.
    """
    downloaded_files = []
    
    for feed_name, feed_url in NVD_FEEDS.items():
        output_path = f"nvdcve-2.0-{feed_name}.json"
        
        # Skip downloading if file exists and is less than 1 day old (except for recent/modified)
        if os.path.exists(output_path) and feed_name not in ['recent', 'modified']:
            file_age = time.time() - os.path.getmtime(output_path)
            file_size = os.path.getsize(output_path)
            if file_size > 0 and file_age < 86400:
                logger.info(f"Using existing file for {feed_name} feed: {output_path} ({file_size} bytes)")
                downloaded_files.append(output_path)
                continue
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Downloading NVD feed: {feed_name} from {feed_url} (attempt {attempt+1}/{max_retries})")
                response = requests.get(feed_url, stream=True, timeout=120)
                response.raise_for_status()
                
                logger.info(f"Decompressing {feed_name} feed")
                json_data = gzip.decompress(response.content)
                data = json.loads(json_data)
                
                logger.info(f"Saving {feed_name} feed to {output_path}")
                with open(output_path, 'wb') as f:
                    f.write(json_data)
                    
                file_size = os.path.getsize(output_path)
                logger.info(f"Saved {output_path}: {file_size} bytes")
                downloaded_files.append(output_path)
                
                # Add delay between downloads (except for last item)
                if feed_name not in ['recent', 'modified']:
                    time.sleep(1)
                
                break
                
            except requests.exceptions.RequestException as e:
                logger.warning(f"Error downloading {feed_name} feed (attempt {attempt+1}): {e}")
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error(f"Failed to download {feed_name} feed after {max_retries} attempts")
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON in {feed_name} feed: {e}")
                break
            except Exception as e:
                logger.error(f"Unexpected error processing {feed_name} feed: {e}")
                break
    
    return downloaded_files

def download_epss_data(url, backup_path=None):
    """
    Downloads the EPSS data from the URL and returns a DataFrame.
    If the download fails, tries to use the backup file if available.
    
    Returns:
        pandas.DataFrame: DataFrame containing EPSS data.
    """
    try:
        logger.info(f"Downloading EPSS data from {url}")
        epss_df = pd.read_csv(url, comment='#', compression='gzip')
        if backup_path:
            os.makedirs(os.path.dirname(backup_path), exist_ok=True)
            epss_df.to_csv(backup_path, index=False)
            logger.info(f"Saved EPSS backup to {backup_path}")
            
        return epss_df
    except Exception as e:
        logger.warning(f"Failed to download EPSS data: {e}")
        if backup_path and os.path.exists(backup_path):
            logger.info(f"Using backup EPSS data from {backup_path}")
            return pd.read_csv(backup_path)
        else:
            logger.error("No backup EPSS data available")
            raise

def get_primary_metric(metrics_array):
    """
    Extract primary CVSS metric from array of metrics.
    
    Prefers metrics in this order:
    1. Type = 'Primary'
    2. Source = 'nvd@nist.gov'
    3. First entry in array
    
    Args:
        metrics_array (list): Array of CVSS metric objects
        
    Returns:
        dict: Selected metric object, or None if array is empty
    """
    if not metrics_array:
        return None
    
    # Prefer Primary type
    primary = [m for m in metrics_array if m.get('type') == 'Primary']
    if primary:
        return primary[0]
    
    # Prefer nvd@nist.gov source
    nvd_source = [m for m in metrics_array if 'nvd@nist.gov' in m.get('source', '')]
    if nvd_source:
        return nvd_source[0]
    
    # Fallback to first entry
    return metrics_array[0]


def extract_cvss_metrics(entry):
    """
    Extract CVSS metrics from JSON 2.0 entry with correct baseSeverity handling.
    
    🚨 CRITICAL: baseSeverity location differs by CVSS version!
    - CVSS v2: baseSeverity is at metric level (outside cvssData)
    - CVSS v3.0/3.1/4.0: baseSeverity is inside cvssData
    
    Args:
        entry (dict): The 'cve' object from JSON 2.0 vulnerability
        
    Returns:
        tuple: (version, baseScore, baseSeverity, vectorString)
               Returns ('N/A', 'N/A', 'N/A', 'N/A') if no CVSS data found
    """
    metrics = entry.get('metrics', {})
    
    # Try CVSS 4.0 first (newest)
    if 'cvssMetricV40' in metrics:
        metric = get_primary_metric(metrics['cvssMetricV40'])
        if metric:
            cvss_data = metric.get('cvssData', {})
            return (
                '4.0',
                cvss_data.get('baseScore', 'N/A'),
                cvss_data.get('baseSeverity', 'N/A'),  # Inside cvssData for v4.0
                cvss_data.get('vectorString', 'N/A')
            )
    
    # Try CVSS 3.1
    elif 'cvssMetricV31' in metrics:
        metric = get_primary_metric(metrics['cvssMetricV31'])
        if metric:
            cvss_data = metric.get('cvssData', {})
            return (
                '3.1',
                cvss_data.get('baseScore', 'N/A'),
                cvss_data.get('baseSeverity', 'N/A'),  # Inside cvssData for v3.1
                cvss_data.get('vectorString', 'N/A')
            )
    
    # Try CVSS 3.0
    elif 'cvssMetricV30' in metrics:
        metric = get_primary_metric(metrics['cvssMetricV30'])
        if metric:
            cvss_data = metric.get('cvssData', {})
            return (
                '3.0',
                cvss_data.get('baseScore', 'N/A'),
                cvss_data.get('baseSeverity', 'N/A'),  # Inside cvssData for v3.0
                cvss_data.get('vectorString', 'N/A')
            )
    
    # Try CVSS 2.0 (legacy)
    elif 'cvssMetricV2' in metrics:
        metric = get_primary_metric(metrics['cvssMetricV2'])
        if metric:
            cvss_data = metric.get('cvssData', {})
            return (
                '2.0',
                cvss_data.get('baseScore', 'N/A'),
                metric.get('baseSeverity', 'N/A'),  # ⚠️ OUTSIDE cvssData for v2!
                cvss_data.get('vectorString', 'N/A')
            )
    
    # No CVSS data found
    return ('N/A', 'N/A', 'N/A', 'N/A')


def process_nvd_files():
    """
    Processes the NVD JSON files and returns a DataFrame containing the data.
    
    Returns:
        pandas.DataFrame: DataFrame with extracted NVD data.
    """
    nvd_dict = []
    json_files = list(Path('.').glob('*.json'))
    
    if not json_files:
        logger.warning("No NVD JSON files found in the current directory")
        return pd.DataFrame()

    for file_path in json_files:
        logger.info(f'Processing {file_path.name}')
        try:
            with file_path.open('r', encoding='utf-8') as file:
                data = json.load(file)
                # JSON 2.0 uses 'vulnerabilities' instead of 'CVE_Items'
                vulnerabilities = data.get('vulnerabilities', [])
                logger.info(f'CVEs in {file_path.name}: {len(vulnerabilities)}')

                for vuln_item in vulnerabilities:
                    try:
                        # JSON 2.0: unwrap the 'cve' object
                        entry = vuln_item.get('cve', {})
                        
                        # JSON 2.0: Filter by vulnStatus instead of checking for '**'
                        vuln_status = entry.get('vulnStatus', '')
                        if vuln_status in ['Rejected', 'Reserved']:
                            continue
                        
                        # JSON 2.0: CVE ID is directly under 'id'
                        cve = entry.get('id', 'N/A')
                        
                        # JSON 2.0: Extract CVSS metrics using helper function
                        cvss_version, base_score, base_severity, base_vector = extract_cvss_metrics(entry)
                        
                        # JSON 2.0: sourceIdentifier replaces ASSIGNER
                        assigner = entry.get('sourceIdentifier', 'N/A')
                        
                        # JSON 2.0: dates are directly under cve object
                        published_date = entry.get('published', '')
                        last_modified_date = entry.get('lastModified', '')
                        
                        # JSON 2.0: descriptions array, filter for English
                        descriptions = entry.get('descriptions', [])
                        description = next(
                            (d.get('value', 'N/A') for d in descriptions if d.get('lang') == 'en'),
                            'N/A'
                        )

                        # Create dictionary entry for this CVE
                        dict_entry = {
                            'cve': cve,
                            'cvss_version': cvss_version,
                            'base_score': base_score,
                            'base_severity': base_severity,
                            'base_vector': base_vector,
                            'assigner': assigner,
                            'published_date': published_date,
                            'last_modified_date': last_modified_date,
                            'description': description
                        }
                        nvd_dict.append(dict_entry)
                    except Exception as e:
                        cve_id = vuln_item.get('cve', {}).get('id', 'Unknown')
                        logger.warning(f"Error processing entry in {file_path.name} for CVE {cve_id}: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error processing file {file_path.name}: {e}")
            continue

    if not nvd_dict:
        logger.warning("No CVE data extracted from JSON files")
        return pd.DataFrame()
        
    nvd_df = pd.DataFrame(nvd_dict)
    
    # Log version distribution for insights
    if not nvd_df.empty and 'cvss_version' in nvd_df.columns:
        version_counts = nvd_df['cvss_version'].value_counts()
        logger.info(f'CVSS version distribution: {version_counts.to_dict()}')
    
    logger.info(f'Total CVEs extracted from NVD: {nvd_df["cve"].nunique()}')
    return nvd_df

def enrich_df(nvd_df):
    """
    Enriches the dataframe with exploit maturity and temporal scores.
    
    Args:
        nvd_df (pandas.DataFrame): DataFrame containing NVD data.
        
    Returns:
        pandas.DataFrame: Enriched DataFrame with temporal scores.
    """
    if nvd_df.empty:
        logger.warning("No NVD data to enrich")
        return pd.DataFrame()

    logger.info('Loading EPSS data')
    try:
        epss_df = download_epss_data(EPSS_CSV, EPSS_BACKUP)
    except Exception as e:
        logger.error(f"Failed to load EPSS data: {e}")
        return nvd_df

    logger.info('Enriching data with exploit information')
    try:
        enriched_df = enrich_nvd.enrich(nvd_df, epss_df)
    except Exception as e:
        logger.error(f"Error during enrichment: {e}")
        return nvd_df
    
    logger.info('Updating temporal scores based on exploit maturity')
    try:
        cvss_te_df = enrich_nvd.update_temporal_score(enriched_df, enrich_nvd.EPSS_THRESHOLD)
    except Exception as e:
        logger.error(f"Error updating temporal scores: {e}")
        return enriched_df

    # Define the essential columns with both BT and TE data
    essential_columns = [
        'cve',
        'cvss_version',
        'base_score',
        'base_severity',
        'base_vector',
        'assigner',
        'published_date',
        'last_modified_date',
        'epss',
        'cisa_kev',
        'vulncheck_kev',
        'exploitdb',
        'metasploit',
        'nuclei',
        'poc_github',
        'reliability',
        'ease_of_use',
        'effectiveness',
        'quality_score',
        'exploit_sources',
        'exploit_maturity',
        # BT score (standard temporal)
        'cvss-bt_score',
        'cvss-bt_severity',
        'cvss-bt_vector',
        # TE score (enhanced)
        'cvss-te_score',
        'cvss-te_severity'
    ]

    available_columns = [col for col in essential_columns if col in cvss_te_df.columns]
    cvss_te_df = cvss_te_df[available_columns]

    # Flatten multi-line text in description fields
    def flatten_text(x):
        if isinstance(x, str):
            return x.replace('\n', ' ').replace('\r', ' ')
        return x
    cvss_te_df = cvss_te_df.applymap(flatten_text)

    # Convert boolean columns to integers
    bool_columns = ['cisa_kev', 'vulncheck_kev', 'exploitdb', 'metasploit', 'nuclei', 'poc_github']
    for col in bool_columns:
        if col in cvss_te_df.columns:
            cvss_te_df[col] = cvss_te_df[col].astype(int)

    # Sort by published date
    cvss_te_df = cvss_te_df.sort_values(by=['published_date']).reset_index(drop=True)

    # Save the enriched data
    output_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'cvss-te.csv')
    logger.info(f'Saving enriched data to {output_file}')
    cvss_te_df.to_csv(output_file, index=False, mode='w')

    return cvss_te_df

def save_last_run_timestamp(filename=TIMESTAMP_FILE):
    """
    Save the current timestamp as the last run timestamp in a file.
    Uses proper UTC time to match the 'Z' suffix in the ISO 8601 format.
    """
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w', encoding='utf-8') as f:
            # Create a timezone-aware UTC datetime
            utc_now = datetime.now(timezone.utc)
            timestamp = utc_now.strftime('%Y-%m-%dT%H:%M:%SZ')
            f.write(timestamp)
        logger.info(f"Timestamp saved: {timestamp}")
    except Exception as e:
        logger.error(f"Error saving timestamp to {filename}: {e}")

def main():
    """
    Main function to run the NVD processing and enrichment pipeline.
    """
    logger.info("Starting NVD processing and enrichment pipeline")
    
    try:
        create_directories()
        logger.info("Downloading NVD feeds (this may take some time)")
        download_nvd_feeds()
        
        nvd_df = process_nvd_files()
        if nvd_df.empty:
            logger.warning("No NVD data to process. Exiting.")
            return
        
        cve_count = nvd_df['cve'].nunique()
        logger.info(f"Total unique CVEs to process: {cve_count}")
            
        enriched_df = enrich_df(nvd_df)
        if enriched_df.empty:
            logger.warning("Enrichment resulted in empty dataset. Check for errors.")
        
        # Fix any problematic CVEs with unknown scores
        fixed_df = enrich_nvd.recalculate_problem_cves(enriched_df)
        
        # Save final output
        output_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'cvss-te.csv')
        logger.info(f'Saving final data to {output_file}')
        fixed_df.to_csv(output_file, index=False, mode='w')
        
        save_last_run_timestamp(TIMESTAMP_FILE)
        logger.info("NVD processing and enrichment pipeline completed successfully")
    except Exception as e:
        logger.error(f"Unhandled exception in main process: {e}")

if __name__ == "__main__":
    main()