/**
 * CVSS-TE Configuration
 * Application constants and configuration values
 */

const CONFIG = {
    // Data paths
    CSV_PATH: 'cvss-te.csv',
    LAST_RUN_PATH: 'code/last_run.txt',
    
    // EPSS Thresholds
    EPSS_THRESHOLDS: {
        CRITICAL: 0.5,    // 50%+
        HIGH: 0.36,       // 36%+ (EPSS threshold from README)
        MEDIUM: 0.1       // 10-36%
    },
    
    // CVSS Severity Thresholds
    CVSS_THRESHOLDS: {
        CRITICAL: 9.0,    // 9.0+
        HIGH: 7.0,        // 7.0-8.9
        MEDIUM: 4.0       // 4.0-6.9
    },
    
    // Analytics
    GA_ID: 'G-27RZTCLPTE',
    
    // UI Settings
    MAX_RECENT_SEARCHES: 5
};

