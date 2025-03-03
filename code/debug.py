#!/usr/bin/env python3
"""
Debug CVE Script

Usage:
  python debug_cve.py CVE-2021-44228
  python debug_cve.py -f path/to/custom/file.csv CVE-2021-44228
"""

import json
import sys
import os
import argparse
import pandas as pd
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Import the debugging functions
try:
    from enrich_nvd import debug_cvss_calculation, recalculate_problem_cves
except ImportError:
    logger.error("Could not import enrich_nvd. Make sure it's in the same directory or PYTHONPATH.")
    sys.exit(1)

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Debug CVE score calculation')
    parser.add_argument('cve_id', help='CVE ID to debug (e.g., CVE-2021-44228)')
    
    # Get the default path to cvss-te.csv (one directory above)
    default_csv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'cvss-te.csv')
    parser.add_argument('-f', '--file', help=f'Path to custom CSV file (default: {default_csv_path})', default=default_csv_path)
    
    parser.add_argument('-r', '--recalculate', action='store_true', help='Try to recalculate the CVE score')
    parser.add_argument('-o', '--output', help='Save debug info to JSON file')
    
    # Parse arguments
    args = parser.parse_args()
    cve_id = args.cve_id
    csv_file = args.file
    
    # Validate CVE format
    if not cve_id.startswith('CVE-'):
        logger.error(f"Invalid CVE ID format: {cve_id}. Should start with 'CVE-'")
        sys.exit(1)
    
    # Load data
    try:
        logger.info(f"Loading data from {csv_file}")
        df = pd.read_csv(csv_file)
        logger.info(f"Loaded {len(df)} CVEs")
    except Exception as e:
        logger.error(f"Error loading CSV file: {e}")
        sys.exit(1)
    
    # Check if CVE exists in data
    if cve_id not in df['cve'].values:
        logger.error(f"CVE {cve_id} not found in the dataset")
        sys.exit(1)
    
    # Debug CVE
    logger.info(f"Debugging {cve_id}")
    debug_info = debug_cvss_calculation(cve_id, df)
    
    # Print debug info
    print("\n" + "="*80)
    print(f"DEBUG INFORMATION FOR {cve_id}")
    print("="*80 + "\n")
    print(json.dumps(debug_info, indent=2))
    
    # Recalculate if requested
    if args.recalculate:
        print("\n" + "="*80)
        print(f"RECALCULATING {cve_id}")
        print("="*80 + "\n")
        
        # Create a smaller dataframe with just the problematic CVE
        problem_df = df[df['cve'] == cve_id].copy()
        
        # Try to recalculate the scores
        fixed_df = recalculate_problem_cves(problem_df)
        
        # Extract and print the fixed row
        fixed_row = fixed_df.iloc[0]
        print("\nRECALCULATED SCORES:")
        print(f"CVSS-BT Score:    {fixed_row.get('cvss-bt_score', 'N/A')}")
        print(f"CVSS-BT Severity: {fixed_row.get('cvss-bt_severity', 'N/A')}")
        print(f"CVSS-TE Score:    {fixed_row.get('cvss-te_score', 'N/A')}")
        print(f"CVSS-TE Severity: {fixed_row.get('cvss-te_severity', 'N/A')}")
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(debug_info, f, indent=2)
        logger.info(f"Debug information saved to {args.output}")
    
    print("\nDebug complete.")

if __name__ == "__main__":
    main()