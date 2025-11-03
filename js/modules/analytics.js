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

    /**
     * Track page view with custom properties
     * @param {string} pageName - Page name (e.g., "dashboard", "lookup")
     * @param {Object} properties - Additional properties
     */
    trackPageView(pageName, properties = {}) {
        this.track('page_view', {
            'page_name': pageName,
            ...properties
        });
    }

    /**
     * Track dashboard section interaction
     * @param {string} section - Section name (e.g., "cisa_kevs", "recent_cves", "emerging_threats")
     * @param {string} action - Action type (e.g., "view", "filter", "sort")
     * @param {Object} properties - Additional properties
     */
    trackDashboardSection(section, action, properties = {}) {
        this.track('dashboard_section', {
            'section': section,
            'action': action,
            ...properties
        });
    }

    /**
     * Track banner interaction
     * @param {string} banner - Banner identifier
     * @param {string} action - Action taken (e.g., "view", "dismiss", "click_learn_more")
     */
    trackBanner(banner, action) {
        this.track('banner_interaction', {
            'banner_id': banner,
            'action': action
        });
    }

    /**
     * Track modal interaction
     * @param {string} modal - Modal identifier
     * @param {string} action - Action taken (e.g., "open", "close", "click_link")
     * @param {Object} properties - Additional properties
     */
    trackModal(modal, action, properties = {}) {
        this.track('modal_interaction', {
            'modal_id': modal,
            'action': action,
            ...properties
        });
    }

    /**
     * Track CVE card click from dashboard
     * @param {string} cveId - CVE ID
     * @param {string} source - Source section (e.g., "cisa_kevs", "recent_cves", "emerging_threats")
     * @param {string} severity - CVSS-TE severity
     */
    trackCVECardClick(cveId, source, severity) {
        this.track('cve_card_click', {
            'cve_id': cveId,
            'source_section': source,
            'cvss_te_severity': severity
        });
    }

    /**
     * Track quick search usage
     * @param {string} searchTerm - Search term used
     * @param {string} source - Where search was initiated (e.g., "dashboard_hero", "dashboard_navbar")
     */
    trackQuickSearch(searchTerm, source) {
        this.track('quick_search', {
            'search_term': searchTerm,
            'source': source
        });
    }

    /**
     * Track navigation between pages
     * @param {string} from - Source page
     * @param {string} to - Destination page
     * @param {string} trigger - What triggered navigation (e.g., "navbar", "button", "cve_card")
     */
    trackNavigation(from, to, trigger) {
        this.track('navigation', {
            'from_page': from,
            'to_page': to,
            'trigger': trigger
        });
    }

    /**
     * Track dashboard statistics view
     * @param {Object} stats - Statistics object with counts
     */
    trackDashboardStats(stats) {
        this.track('dashboard_stats_view', {
            'total_cves': stats.total || 0,
            'cisa_kevs': stats.cisaKevs || 0,
            'exploits': stats.exploits || 0,
            'critical': stats.critical || 0,
            'high': stats.high || 0,
            'medium': stats.medium || 0
        });
    }

    /**
     * Track filter/sort change on dashboard sections
     * @param {string} section - Section name
     * @param {string} type - "filter" or "sort"
     * @param {string} value - Selected value
     */
    trackDashboardControl(section, type, value) {
        this.track('dashboard_control', {
            'section': section,
            'control_type': type,
            'value': value
        });
    }

    /**
     * Track data load performance
     * @param {string} dataType - Type of data loaded (e.g., "csv", "kev")
     * @param {number} loadTime - Load time in milliseconds
     * @param {boolean} success - Whether load was successful
     */
    trackDataLoad(dataType, loadTime, success) {
        this.track('data_load', {
            'data_type': dataType,
            'load_time_ms': loadTime,
            'success': success
        });
    }

    /**
     * Track external link clicks
     * @param {string} url - URL being navigated to
     * @param {string} context - Where link was clicked (e.g., "modal", "banner", "footer")
     */
    trackExternalLink(url, context) {
        this.track('external_link_click', {
            'url': url,
            'context': context
        });
    }
}

