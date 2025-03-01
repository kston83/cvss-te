from datetime import datetime, date
from pathlib import Path
import pandas as pd
import logging
import json
import requests
import gzip
import io
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
    import enrich_nvd as enrich_nvd
except ImportError:
    logger.error("Could not import enrich module. Make sure enrich.py is in the same directory.")
    sys.exit(1)

# Constants
EPSS_CSV = f'https://epss.cyentia.com/epss_scores-{date.today()}.csv.gz'
EPSS_BACKUP = './data/epss/epss_scores.csv'  # Backup location
TIMESTAMP_FILE = './code/last_run.txt'

# NVD Feed URLs - complete history from 2002 to present
def generate_nvd_feeds():
    """Generate a dictionary of all NVD feeds from 2002 to present year"""
    feeds = {
        'recent': 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz',
        'modified': 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz',
    }
    
    current_year = date.today().year
    
    # Add yearly feeds from 2002 to current year
    for year in range(2002, current_year + 1):
        feeds[str(year)] = f'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz'
    
    return feeds

NVD_FEEDS = generate_nvd_feeds()


def create_directories():
    """Create necessary directories for the script"""
    os.makedirs('./data/epss', exist_ok=True)
    os.makedirs('./code', exist_ok=True)


def download_nvd_feeds(max_retries=3, retry_delay=5):
    """
    Download NVD feeds, decompress them, and save to the current directory
    
    Args:
        max_retries (int): Maximum number of retry attempts for each feed
        retry_delay (int): Delay in seconds between retries
    
    Returns:
        list: List of downloaded JSON filenames
    """
    downloaded_files = []
    
    for feed_name, feed_url in NVD_FEEDS.items():
        output_path = f"nvdcve-{feed_name}.json"
        
        # Skip if file exists and is recent (less than 24 hours old)
        if os.path.exists(output_path) and feed_name not in ['recent', 'modified']:
            file_age = time.time() - os.path.getmtime(output_path)
            file_size = os.path.getsize(output_path)
            if file_size > 0 and file_age < 86400:  # 24 hours in seconds
                logger.info(f"Using existing file for {feed_name} feed: {output_path} ({file_size} bytes)")
                downloaded_files.append(output_path)
                continue
        
        # Attempt to download with retries
        for attempt in range(max_retries):
            try:
                logger.info(f"Downloading NVD feed: {feed_name} from {feed_url} (attempt {attempt+1}/{max_retries})")
                response = requests.get(feed_url, stream=True, timeout=120)
                response.raise_for_status()
                
                # Decompress and load the JSON
                logger.info(f"Decompressing {feed_name} feed")
                json_data = gzip.decompress(response.content)
                
                # Validate JSON before saving
                data = json.loads(json_data)
                
                # Save to file
                logger.info(f"Saving {feed_name} feed to {output_path}")
                with open(output_path, 'wb') as f:
                    f.write(json_data)
                    
                file_size = os.path.getsize(output_path)
                logger.info(f"Saved {output_path}: {file_size} bytes")
                downloaded_files.append(output_path)
                
                # Sleep to avoid overloading the NVD server
                if feed_name not in ['recent', 'modified']:
                    time.sleep(1)  # Be polite to the NVD server
                
                break  # Exit retry loop on success
                
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
    
    Args:
        url (str): URL to download the EPSS data from
        backup_path (str): Path to backup EPSS file
        
    Returns:
        pandas.DataFrame: DataFrame containing EPSS data
    """
    try:
        logger.info(f"Downloading EPSS data from {url}")
        epss_df = pd.read_csv(url, comment='#', compression='gzip')
        
        # Save a backup
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


def process_nvd_files():
    """
    Processes the NVD JSON files and returns a dataframe.

    Returns:
        nvd_df: A dataframe containing the NVD data.
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
                vulnerabilities = data.get('CVE_Items', [])
                logger.info(f'CVEs in {file_path.name}: {len(vulnerabilities)}')

                for entry in vulnerabilities:
                    try:
                        # Skip entries with descriptions starting with **
                        if entry['cve']['description']['description_data'][0]['value'].startswith('**'):
                            continue
                            
                        cve = entry['cve']['CVE_data_meta']['ID']
                        
                        # Extract CVSS information based on available version
                        if 'metricV40' in entry.get('impact', {}):
                            cvss_version = '4.0'
                            base_score = entry['impact']['metricV40']['baseScore']
                            base_severity = entry['impact']['metricV40']['baseSeverity']
                            base_vector = entry['impact']['metricV40']['vectorString']
                        elif 'baseMetricV3' in entry.get('impact', {}):
                            cvss_version = entry['impact']['baseMetricV3']['cvssV3']['version']
                            base_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
                            base_severity = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                            base_vector = entry['impact']['baseMetricV3']['cvssV3']['vectorString']
                        else:
                            cvss_version = entry.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('version', 'N/A')
                            base_score = entry.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 'N/A')
                            base_severity = entry.get('impact', {}).get('baseMetricV2', {}).get('severity', 'N/A')
                            base_vector = entry.get('impact', {}).get('baseMetricV2', {}).get('cvssV2', {}).get('vectorString', 'N/A')
                        
                        # Extract other metadata
                        assigner = entry['cve']['CVE_data_meta']['ASSIGNER']
                        published_date = entry['publishedDate']
                        description = entry['cve']['description']['description_data'][0]['value']

                        dict_entry = {
                            'cve': cve,
                            'cvss_version': cvss_version,
                            'base_score': base_score,
                            'base_severity': base_severity,
                            'base_vector': base_vector,
                            'assigner': assigner,
                            'published_date': published_date,
                            'description': description
                        }
                        nvd_dict.append(dict_entry)
                    except Exception as e:
                        logger.warning(f"Error processing entry in {file_path.name}: {e}")
                        continue
        except Exception as e:
            logger.error(f"Error processing file {file_path.name}: {e}")
            continue

    # Create DataFrame
    if not nvd_dict:
        logger.warning("No CVE data extracted from JSON files")
        return pd.DataFrame()
        
    nvd_df = pd.DataFrame(nvd_dict)
    logger.info(f'CVEs with CVSS scores from NVD: {nvd_df["cve"].nunique()}')

    return nvd_df


def enrich_df(nvd_df):
    """
    Enriches the dataframe with exploit maturity and temporal scores.
    
    Args:
        nvd_df (pandas.DataFrame): DataFrame containing NVD data
        
    Returns:
        pandas.DataFrame: Enriched DataFrame with temporal scores
    """
    if nvd_df.empty:
        logger.warning("No NVD data to enrich")
        return pd.DataFrame()

    logger.info('Loading EPSS data')
    try:
        epss_df = download_epss_data(EPSS_CSV, EPSS_BACKUP)
    except Exception as e:
        logger.error(f"Failed to load EPSS data: {e}")
        return nvd_df  # Return original data if EPSS data can't be loaded

    logger.info('Enriching data with exploit information')
    try:
        enriched_df = enrich_nvd.enrich(nvd_df, epss_df)
    except Exception as e:
        logger.error(f"Error during enrichment: {e}")
        return nvd_df
    
    logger.info('Updating temporal scores based on exploit maturity')
    try:
        cvss_bt_df = enrich_nvd.update_temporal_score(enriched_df, enrich_nvd.EPSS_THRESHOLD)
    except Exception as e:
        logger.error(f"Error updating temporal scores: {e}")
        return enriched_df
    
    # Select and order columns
    try:
        # List of essential columns
        essential_columns = [
            'cve',
            'cvss-bt_score',
            'cvss-bt_severity',
            'cvss-bt_vector',
            'cvss_version',
            'base_score',
            'base_severity',
            'base_vector',
            'assigner',
            'published_date',
            'epss',
            'cisa_kev',
            'vulncheck_kev',
            'exploitdb',
            'metasploit',
            'nuclei',
            'poc_github'
        ]
        
        # Add additional columns from the new enhanced script if they exist
        enhanced_columns = [
            'reliability', 
            'ease_of_use', 
            'effectiveness', 
            'quality_score', 
            'exploit_sources',
            'cvss-vt_score',
            'cvss-vt_severity',
            'exploit_quality_explanation',
            'cvss-vt_explanation'
        ]
        
        # Build the final column list based on what's available
        columns = essential_columns + [col for col in enhanced_columns if col in cvss_bt_df.columns]
        
        # Select only columns that exist in the dataframe
        available_columns = [col for col in columns if col in cvss_bt_df.columns]
        cvss_bt_df = cvss_bt_df[available_columns]
        
        # Sort and reset index
        cvss_bt_df = cvss_bt_df.sort_values(by=['published_date'])
        cvss_bt_df = cvss_bt_df.reset_index(drop=True)
        
        # Save the results
        output_file = 'cvss-vt.csv'
        logger.info(f'Saving enriched data to {output_file}')
        cvss_bt_df.to_csv(output_file, index=False, mode='w')
        
        return cvss_bt_df
    except Exception as e:
        logger.error(f"Error formatting and saving results: {e}")
        return cvss_bt_df


def save_last_run_timestamp(filename=TIMESTAMP_FILE):
    """
    Save the current timestamp as the last run timestamp in a file.

    Args:
        filename (str): The name of the file to save the timestamp.
    """
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
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
        # Create necessary directories
        create_directories()
        
        # Download NVD feeds
        logger.info("Downloading NVD feeds (this may take some time)")
        download_nvd_feeds()
        
        # Process NVD files
        nvd_df = process_nvd_files()
        if nvd_df.empty:
            logger.warning("No NVD data to process. Exiting.")
            return
        
        # Log number of CVEs for reporting
        cve_count = nvd_df['cve'].nunique()
        logger.info(f"Total unique CVEs to process: {cve_count}")
            
        # Enrich the data
        enriched_df = enrich_df(nvd_df)
        if enriched_df.empty:
            logger.warning("Enrichment resulted in empty dataset. Check for errors.")
        
        # Save the timestamp
        save_last_run_timestamp(TIMESTAMP_FILE)
        
        logger.info("NVD processing and enrichment pipeline completed successfully")
    except Exception as e:
        logger.error(f"Unhandled exception in main process: {e}")


if __name__ == "__main__":
    main()