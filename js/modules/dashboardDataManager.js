/**
 * DashboardDataManager Module
 * Handles data aggregation and filtering for dashboard
 */

import { DataManager } from './dataManager.js';

export class DashboardDataManager {
    constructor(dataManager) {
        this.dataManager = dataManager;
    }

    /**
     * Get CISA Known Exploited Vulnerabilities
     * @param {number} limit - Number of results (default: 10)
     * @param {string} sortBy - Sort criteria (default: 'date_desc' for most recent)
     * @returns {Array} CISA KEVs sorted by specified criteria
     */
    getCisaKevs(limit = 10, sortBy = 'date_desc') {
        const data = this.dataManager.getData();
        if (!data) return [];
        
        const kevs = data.filter(cve => cve.cisa_kev === 1 || cve.cisa_kev === true || cve.cisa_kev === '1');
        
        // Sort based on criteria
        let sorted;
        switch(sortBy) {
            case 'cvss-te_desc':
                sorted = kevs.sort((a, b) => (parseFloat(b['cvss-te_score']) || 0) - (parseFloat(a['cvss-te_score']) || 0));
                break;
            case 'cvss-te_asc':
                sorted = kevs.sort((a, b) => (parseFloat(a['cvss-te_score']) || 0) - (parseFloat(b['cvss-te_score']) || 0));
                break;
            case 'date_desc':
                // Sort by cisa_kev_date_added (official CISA date)
                // Fallback to last_modified_date if not enriched
                sorted = kevs.sort((a, b) => {
                    const dateA = new Date(a.cisa_kev_date_added || a.last_modified_date || 0);
                    const dateB = new Date(b.cisa_kev_date_added || b.last_modified_date || 0);
                    return dateB - dateA;
                });
                break;
            case 'date_asc':
                sorted = kevs.sort((a, b) => {
                    const dateA = new Date(a.cisa_kev_date_added || a.last_modified_date || 0);
                    const dateB = new Date(b.cisa_kev_date_added || b.last_modified_date || 0);
                    return dateA - dateB;
                });
                break;
            case 'epss_desc':
                sorted = kevs.sort((a, b) => (parseFloat(b.epss) || 0) - (parseFloat(a.epss) || 0));
                break;
            case 'epss_asc':
                sorted = kevs.sort((a, b) => (parseFloat(a.epss) || 0) - (parseFloat(b.epss) || 0));
                break;
            default:
                // Default to most recent (by cisa_kev_date_added)
                sorted = kevs.sort((a, b) => {
                    const dateA = new Date(a.cisa_kev_date_added || a.last_modified_date || 0);
                    const dateB = new Date(b.cisa_kev_date_added || b.last_modified_date || 0);
                    return dateB - dateA;
                });
        }
        
        return sorted.slice(0, limit);
    }

    /**
     * Get recently published CVEs
     * @param {number} days - Number of days back (default: 7)
     * @param {number} limit - Number of results (default: 20)
     * @returns {Array} Recent CVEs
     */
    getRecentCves(days = 7, limit = 20) {
        const data = this.dataManager.getData();
        if (!data) return [];
        
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        
        return data
            .filter(cve => {
                if (!cve.published_date) return false;
                const pubDate = new Date(cve.published_date);
                return pubDate >= cutoffDate;
            })
            .sort((a, b) => new Date(b.published_date) - new Date(a.published_date))
            .slice(0, limit);
    }

    /**
     * Get emerging threats - recent CVEs with exploitation signals
     * @param {number} days - Number of days back (default: 90)
     * @param {number} limit - Number of results (default: 15)
     * @returns {Array} Emerging threat CVEs
     */
    getEmergingThreats(days = 90, limit = 15) {
        const data = this.dataManager.getData();
        if (!data) return [];
        
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        
        return data
            .filter(cve => {
                // Must be recently published
                if (!cve.published_date) return false;
                const pubDate = new Date(cve.published_date);
                if (pubDate < cutoffDate) return false;
                
                // Must have exploitation signals
                const epss = parseFloat(cve.epss);
                const hasHighEpss = !isNaN(epss) && epss >= 0.3; // 30%+ EPSS
                const hasExploits = cve.exploitdb || cve.metasploit || cve.nuclei || cve.poc_github;
                const isKev = cve.cisa_kev === 1 || cve.cisa_kev === true || cve.cisa_kev === '1';
                
                return hasHighEpss || hasExploits || isKev;
            })
            .sort((a, b) => {
                // Sort by CVSS-TE score (best overall threat assessment)
                return (parseFloat(b['cvss-te_score']) || 0) - (parseFloat(a['cvss-te_score']) || 0);
            })
            .slice(0, limit);
    }

    /**
     * Get dashboard statistics
     * @returns {Object} Statistics object
     */
    getStatistics() {
        const data = this.dataManager.getData();
        if (!data) return null;
        
        return {
            totalCves: data.length,
            cisaKevs: data.filter(cve => cve.cisa_kev === 1 || cve.cisa_kev === true || cve.cisa_kev === '1').length,
            criticalCves: data.filter(cve => cve['cvss-te_severity'] === 'CRITICAL').length,
            highCves: data.filter(cve => cve['cvss-te_severity'] === 'HIGH').length,
            highEpss: data.filter(cve => {
                const epss = parseFloat(cve.epss);
                return !isNaN(epss) && epss >= 0.36;
            }).length,
            withExploits: data.filter(cve => 
                cve.exploitdb || cve.metasploit || cve.nuclei || cve.poc_github
            ).length,
            recentCount: this.getRecentCves(7).length
        };
    }

    /**
     * Get CVEs with active exploits
     * @param {number} limit - Number of results
     * @returns {Array} CVEs with exploit code
     */
    getCvesWithExploits(limit = 15) {
        const data = this.dataManager.getData();
        if (!data) return [];
        
        return data
            .filter(cve => cve.exploitdb || cve.metasploit || cve.nuclei || cve.poc_github)
            .sort((a, b) => (parseFloat(b['cvss-te_score']) || 0) - (parseFloat(a['cvss-te_score']) || 0))
            .slice(0, limit);
    }

    /**
     * Get CVEs by severity
     * @param {string} severity - Severity level (CRITICAL, HIGH, MEDIUM, LOW)
     * @param {number} limit - Number of results
     * @returns {Array} CVEs of specified severity
     */
    getCvesBySeverity(severity, limit = 20) {
        const data = this.dataManager.getData();
        if (!data) return [];
        
        return data
            .filter(cve => cve['cvss-te_severity'] === severity)
            .sort((a, b) => (parseFloat(b['cvss-te_score']) || 0) - (parseFloat(a['cvss-te_score']) || 0))
            .slice(0, limit);
    }

    /**
     * Sort CVE array by various criteria
     * @param {Array} cves - Array of CVEs to sort
     * @param {string} sortBy - Sort criteria (cvss-te_desc, cvss-te_asc, date_desc, date_asc, epss_desc, epss_asc)
     * @returns {Array} Sorted array
     */
    sortCves(cves, sortBy) {
        if (!cves || cves.length === 0) return [];
        
        const sorted = [...cves]; // Create a copy to avoid mutating original
        
        switch(sortBy) {
            case 'cvss-te_desc':
                return sorted.sort((a, b) => (parseFloat(b['cvss-te_score']) || 0) - (parseFloat(a['cvss-te_score']) || 0));
            case 'cvss-te_asc':
                return sorted.sort((a, b) => (parseFloat(a['cvss-te_score']) || 0) - (parseFloat(b['cvss-te_score']) || 0));
            case 'date_desc':
                return sorted.sort((a, b) => new Date(b.published_date || 0) - new Date(a.published_date || 0));
            case 'date_asc':
                return sorted.sort((a, b) => new Date(a.published_date || 0) - new Date(b.published_date || 0));
            case 'epss_desc':
                return sorted.sort((a, b) => (parseFloat(b.epss) || 0) - (parseFloat(a.epss) || 0));
            case 'epss_asc':
                return sorted.sort((a, b) => (parseFloat(a.epss) || 0) - (parseFloat(b.epss) || 0));
            default:
                return sorted;
        }
    }
}

