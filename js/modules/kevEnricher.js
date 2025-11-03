/**
 * KEV Enricher Module
 * Fetches CISA KEV catalog and enriches CVE data with dateAdded
 */

const KEV_LOCAL_PATH = 'data/kev/known_exploited_vulnerabilities.json'; // Local fallback
const KEV_REMOTE_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'; // CISA live feed
const KEV_CACHE_KEY = 'cisa_kev_cache';
const KEV_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours

export class KevEnricher {
    constructor() {
        this.kevData = null;
        this.kevMap = new Map(); // CVE ID -> KEV details
    }

    /**
     * Load KEV data from cache or fetch fresh
     * @returns {Promise<void>}
     */
    async loadKevData() {
        try {
            // Try to load from cache first
            const cached = this.loadFromCache();
            if (cached) {
                this.kevData = cached;
                this.buildKevMap();
                console.log(`Loaded ${this.kevMap.size} KEVs from cache`);
                return;
            }

            // Try remote first (most up-to-date), then fall back to local
            console.log('Fetching CISA KEV catalog...');
            let response;
            let source = 'remote';
            
            try {
                response = await fetch(KEV_REMOTE_URL);
                if (!response.ok) throw new Error(`Remote fetch failed: ${response.status}`);
            } catch (remoteError) {
                console.warn('Remote KEV fetch failed, trying local fallback:', remoteError.message);
                try {
                    response = await fetch(KEV_LOCAL_PATH);
                    if (!response.ok) throw new Error(`Local fetch failed: ${response.status}`);
                    source = 'local';
                } catch (localError) {
                    throw new Error(`Both remote and local KEV fetches failed: ${remoteError.message}, ${localError.message}`);
                }
            }

            this.kevData = await response.json();
            
            // Save to cache
            this.saveToCache();
            
            // Build the lookup map
            this.buildKevMap();
            
            console.log(`Loaded ${this.kevMap.size} KEVs from ${source} (catalog version: ${this.kevData.catalogVersion})`);
        } catch (error) {
            console.error('Failed to load KEV data:', error);
            // Continue without KEV enrichment rather than blocking
            this.kevMap = new Map();
        }
    }

    /**
     * Build a Map for fast KEV lookups
     */
    buildKevMap() {
        if (!this.kevData || !this.kevData.vulnerabilities) {
            return;
        }

        this.kevMap.clear();
        for (const vuln of this.kevData.vulnerabilities) {
            this.kevMap.set(vuln.cveID, {
                dateAdded: vuln.dateAdded,
                vendorProject: vuln.vendorProject,
                product: vuln.product,
                shortDescription: vuln.shortDescription,
                dueDate: vuln.dueDate,
                knownRansomwareCampaignUse: vuln.knownRansomwareCampaignUse
            });
        }
    }

    /**
     * Enrich CVE array with KEV dateAdded
     * @param {Array} cveArray - Array of CVE objects
     * @returns {Array} Enriched CVE array
     */
    enrichCves(cveArray) {
        if (!cveArray || cveArray.length === 0) {
            return cveArray;
        }

        if (this.kevMap.size === 0) {
            return cveArray;
        }

        let enrichedCount = 0;
        const enriched = cveArray.map(cve => {
            // Only enrich if it's a KEV
            if (cve.cisa_kev && this.kevMap.has(cve.cve)) {
                const kevDetails = this.kevMap.get(cve.cve);
                enrichedCount++;
                return {
                    ...cve,
                    cisa_kev_date_added: kevDetails.dateAdded,
                    kev_due_date: kevDetails.dueDate,
                    kev_ransomware: kevDetails.knownRansomwareCampaignUse,
                    kev_description: kevDetails.shortDescription
                };
            }
            return cve;
        });

        console.log(`Enriched ${enrichedCount} KEVs with CISA dateAdded`);
        return enriched;
    }

    /**
     * Get KEV details for a specific CVE
     * @param {string} cveId - CVE ID
     * @returns {Object|null} KEV details or null
     */
    getKevDetails(cveId) {
        return this.kevMap.get(cveId) || null;
    }

    /**
     * Load KEV data from localStorage cache
     * @returns {Object|null} Cached data or null
     */
    loadFromCache() {
        try {
            const cached = localStorage.getItem(KEV_CACHE_KEY);
            if (!cached) return null;

            const { data, timestamp } = JSON.parse(cached);
            const age = Date.now() - timestamp;

            // Check if cache is still valid
            if (age < KEV_CACHE_DURATION) {
                return data;
            }

            // Cache expired, remove it
            localStorage.removeItem(KEV_CACHE_KEY);
            return null;
        } catch (error) {
            console.warn('Failed to load KEV cache:', error);
            return null;
        }
    }

    /**
     * Save KEV data to localStorage cache
     */
    saveToCache() {
        try {
            const cacheData = {
                data: this.kevData,
                timestamp: Date.now()
            };
            localStorage.setItem(KEV_CACHE_KEY, JSON.stringify(cacheData));
        } catch (error) {
            console.warn('Failed to save KEV cache:', error);
            // localStorage might be full or disabled, continue without caching
        }
    }

    /**
     * Clear the KEV cache (useful for debugging)
     */
    clearCache() {
        localStorage.removeItem(KEV_CACHE_KEY);
        console.log('KEV cache cleared');
    }

    /**
     * Get cache age in hours
     * @returns {number|null} Age in hours or null if not cached
     */
    getCacheAge() {
        try {
            const cached = localStorage.getItem(KEV_CACHE_KEY);
            if (!cached) return null;

            const { timestamp } = JSON.parse(cached);
            const ageMs = Date.now() - timestamp;
            return Math.round(ageMs / (60 * 60 * 1000));
        } catch (error) {
            return null;
        }
    }
}

