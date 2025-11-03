/**
 * SearchEngine Module
 * Handles CVE ID parsing, searching, filtering, and sorting
 */

export class SearchEngine {
    constructor(dataManager) {
        this.dataManager = dataManager;
    }

    /**
     * Parse user input into valid CVE IDs
     * @param {string} input - Raw user input
     * @returns {Array<string>} Array of valid CVE IDs
     */
    parseInput(input) {
        if (!input) return [];

        return input
            .split(',')
            .map(cve => {
                cve = cve.trim().toUpperCase();
                // Add CVE- prefix if missing (e.g., "2024-1234" -> "CVE-2024-1234")
                if (cve.match(/^\d{4}-\d+$/)) {
                    return 'CVE-' + cve;
                }
                return cve;
            })
            .filter(cve => cve.match(/^CVE-\d{4}-\d+$/));
    }

    /**
     * Search for CVEs by IDs
     * @param {Array<string>} cveIds - Array of CVE IDs to search for
     * @returns {Array<Object>} Array of found CVE objects
     */
    search(cveIds) {
        return this.dataManager.findCVEs(cveIds);
    }

    /**
     * Filter CVEs by severity
     * @param {Array<Object>} results - CVE results to filter
     * @param {string} severity - Severity level (e.g., "CRITICAL", "HIGH")
     * @returns {Array<Object>} Filtered results
     */
    filter(results, severity) {
        if (!severity) return results;
        
        return results.filter(cve => cve['cvss-te_severity'] === severity);
    }

    /**
     * Sort CVEs by various criteria
     * @param {Array<Object>} results - CVE results to sort
     * @param {string} sortBy - Sort criteria
     * @returns {Array<Object>} Sorted results
     */
    sort(results, sortBy) {
        const sorted = [...results];

        switch(sortBy) {
            case 'published_date_desc':
                sorted.sort((a, b) => new Date(b.published_date || 0) - new Date(a.published_date || 0));
                break;
            case 'published_date_asc':
                sorted.sort((a, b) => new Date(a.published_date || 0) - new Date(b.published_date || 0));
                break;
            case 'base_score_desc':
                sorted.sort((a, b) => (parseFloat(b.base_score) || 0) - (parseFloat(a.base_score) || 0));
                break;
            case 'base_score_asc':
                sorted.sort((a, b) => (parseFloat(a.base_score) || 0) - (parseFloat(b.base_score) || 0));
                break;
            case 'cvss-bt_score_desc':
                sorted.sort((a, b) => (parseFloat(b['cvss-bt_score']) || 0) - (parseFloat(a['cvss-bt_score']) || 0));
                break;
            case 'cvss-bt_score_asc':
                sorted.sort((a, b) => (parseFloat(a['cvss-bt_score']) || 0) - (parseFloat(b['cvss-bt_score']) || 0));
                break;
            case 'cvss-te_score_desc':
                sorted.sort((a, b) => (parseFloat(b['cvss-te_score']) || 0) - (parseFloat(a['cvss-te_score']) || 0));
                break;
            case 'epss_desc':
                sorted.sort((a, b) => (parseFloat(b.epss) || 0) - (parseFloat(a.epss) || 0));
                break;
        }

        return sorted;
    }

    /**
     * Filter and sort results in one operation
     * @param {Array<Object>} results - CVE results
     * @param {string} severityFilter - Severity filter
     * @param {string} sortBy - Sort criteria
     * @returns {Array<Object>} Filtered and sorted results
     */
    filterAndSort(results, severityFilter, sortBy) {
        let filtered = this.filter(results, severityFilter);
        return this.sort(filtered, sortBy);
    }
}

