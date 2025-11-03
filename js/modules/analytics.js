/**
 * Analytics Module
 * Handles Google Analytics event tracking
 */

export class Analytics {
    constructor(enabled = true) {
        this.enabled = enabled && typeof gtag === 'function';
    }

    /**
     * Track a generic event
     * @param {string} eventName - Event name
     * @param {Object} properties - Event properties
     */
    track(eventName, properties = {}) {
        if (!this.enabled) return;
        gtag('event', eventName, properties);
    }

    /**
     * Track search event
     * @param {string} searchTerm - Search term used
     * @param {number} resultsCount - Number of results found
     */
    trackSearch(searchTerm, resultsCount) {
        this.track('search', {
            'search_term': searchTerm,
            'results_count': resultsCount
        });
    }

    /**
     * Track export event
     * @param {number} count - Number of items exported
     */
    trackExport(count) {
        this.track('export', {
            'items_count': count
        });
    }

    /**
     * Track CVE details view
     * @param {string} cveId - CVE ID
     * @param {string} severity - Severity level
     */
    trackCVEView(cveId, severity) {
        this.track('view_cve_details', {
            'cve_id': cveId,
            'severity': severity
        });
    }

    /**
     * Track filter change
     * @param {string} filterType - Type of filter (e.g., "severity")
     * @param {string} value - Filter value
     */
    trackFilterChange(filterType, value) {
        this.track('filter_change', {
            'filter_type': filterType,
            'filter_value': value
        });
    }

    /**
     * Track sort change
     * @param {string} value - Sort option selected
     */
    trackSortChange(value) {
        this.track('sort_change', {
            'sort_value': value
        });
    }

    /**
     * Track info panel view
     */
    trackInfoPanelView() {
        this.track('view_info_panel');
    }
}

