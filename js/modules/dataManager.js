/**
 * DataManager Module
 * Handles CSV data loading, parsing, and indexing for fast lookups
 */

export class DataManager {
    constructor(csvPath) {
        this.csvPath = csvPath;
        this.data = null;
        this.index = null;
        this.loading = false;
        this.loaded = false;
        this.loadPromise = null;
    }

    /**
     * Load and parse CSV data
     * @returns {Promise<Array>} Parsed CSV data
     */
    async loadData() {
        // Return existing promise if already loading
        if (this.loading) {
            return this.loadPromise;
        }

        // Return data if already loaded
        if (this.loaded && this.data) {
            return Promise.resolve(this.data);
        }

        this.loading = true;

        this.loadPromise = fetch(this.csvPath)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! Status: ${response.status}`);
                }
                return response.text();
            })
            .then(csvText => {
                // Parse CSV using PapaParse
                const parseResult = Papa.parse(csvText, {
                    header: true,
                    dynamicTyping: true,
                    skipEmptyLines: true
                });
                
                if (parseResult.errors && parseResult.errors.length > 0) {
                    console.warn('CSV parsing warnings:', parseResult.errors);
                }
                
                // Filter out invalid rows
                this.data = parseResult.data.filter(row => 
                    row && row.cve && row.cve.startsWith('CVE-')
                );
                
                // Build index for O(1) lookups
                this.buildIndex();
                
                this.loaded = true;
                this.loading = false;
                
                console.log(`Loaded ${this.data.length} CVE records successfully`);
                
                // Track in analytics if available
                if (typeof gtag === 'function') {
                    gtag('event', 'data_loaded', {
                        'cve_count': this.data.length
                    });
                }
                
                return this.data;
            })
            .catch(error => {
                this.loading = false;
                this.loaded = false;
                console.error('Error loading CSV:', error);
                throw error;
            });

        return this.loadPromise;
    }

    /**
     * Build index for fast CVE lookups
     * Creates a Map with CVE ID as key for O(1) access
     */
    buildIndex() {
        if (!this.data) return;
        
        this.index = new Map();
        this.data.forEach(cve => {
            if (cve.cve) {
                this.index.set(cve.cve, cve);
            }
        });
    }

    /**
     * Find CVEs by their IDs
     * @param {Array<string>} cveIds - Array of CVE IDs
     * @returns {Array<Object>} Array of found CVE objects
     */
    findCVEs(cveIds) {
        if (!this.index) {
            console.warn('Index not built yet');
            return [];
        }

        const results = [];
        cveIds.forEach(id => {
            const cve = this.index.get(id);
            if (cve) {
                results.push(cve);
            }
        });

        return results;
    }

    /**
     * Get all data
     * @returns {Array<Object>|null} All CVE data or null if not loaded
     */
    getData() {
        return this.data;
    }

    /**
     * Check if data is loaded
     * @returns {boolean} True if data is loaded
     */
    isLoaded() {
        return this.loaded;
    }

    /**
     * Wait for data to load
     * @returns {Promise<Array>} Promise that resolves when data is loaded
     */
    async waitForLoad() {
        if (this.loaded) {
            return this.data;
        }
        if (this.loading) {
            return this.loadPromise;
        }
        return this.loadData();
    }
}

