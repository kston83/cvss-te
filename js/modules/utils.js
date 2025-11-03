/**
 * Utility Functions
 * Helper functions for formatting, coloring, and data manipulation
 */

/**
 * Format a date string to readable format
 * @param {string} dateString - ISO date string
 * @returns {string} Formatted date (e.g., "Jan 15, 2024")
 */
export function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric' 
    });
}

/**
 * Format EPSS score as percentage
 * @param {number} epssValue - EPSS value (0-1)
 * @returns {string} Formatted percentage (e.g., "45.23%")
 */
export function formatEpssPercentage(epssValue) {
    if (epssValue === null || epssValue === undefined) return '0.00%';
    const value = parseFloat(epssValue);
    if (isNaN(value)) return '0.00%';
    return (value * 100).toFixed(2) + '%';
}

/**
 * Get Tailwind CSS classes for severity score badge
 * @param {number} score - CVSS score (0-10)
 * @returns {string} Tailwind CSS classes
 */
export function getSeverityColor(score) {
    if (!score) return 'bg-gray-400 text-white';
    const numScore = parseFloat(score);
    if (numScore >= CONFIG.CVSS_THRESHOLDS.CRITICAL) return 'bg-red-600 text-white';
    if (numScore >= CONFIG.CVSS_THRESHOLDS.HIGH) return 'bg-orange-600 text-white';
    if (numScore >= CONFIG.CVSS_THRESHOLDS.MEDIUM) return 'bg-yellow-500 text-black';
    return 'bg-green-600 text-white';
}

/**
 * Get CSS class for EPSS progress bar color
 * @param {number} epssScore - EPSS score (0-1)
 * @returns {string} CSS class name
 */
export function getEpssColor(epssScore) {
    if (!epssScore && epssScore !== 0) return 'epss-unknown';
    const score = parseFloat(epssScore);
    if (score >= CONFIG.EPSS_THRESHOLDS.CRITICAL) return 'epss-critical'; // Critical (50%+)
    if (score >= CONFIG.EPSS_THRESHOLDS.HIGH) return 'epss-high';         // High (36%+)
    if (score >= CONFIG.EPSS_THRESHOLDS.MEDIUM) return 'epss-medium';     // Medium (10-36%)
    return 'epss-low';                                                     // Low (<10%)
}

/**
 * Get CSS class for EPSS text color
 * @param {number} epssScore - EPSS score (0-1)
 * @returns {string} CSS class name
 */
export function getEpssTextColor(epssScore) {
    if (!epssScore && epssScore !== 0) return 'epss-text-unknown';
    const score = parseFloat(epssScore);
    if (score >= CONFIG.EPSS_THRESHOLDS.CRITICAL) return 'epss-text-critical';
    if (score >= CONFIG.EPSS_THRESHOLDS.HIGH) return 'epss-text-high';
    if (score >= CONFIG.EPSS_THRESHOLDS.MEDIUM) return 'epss-text-medium';
    return 'epss-text-low';
}

/**
 * Check if CVE has any exploit indicators
 * @param {Object} cve - CVE object
 * @returns {boolean} True if has exploits
 */
export function hasExploits(cve) {
    return cve.exploitdb || cve.metasploit || cve.nuclei || cve.poc_github;
}

/**
 * Create HTML for threat indicator badges
 * @param {Object} cve - CVE object
 * @returns {string} HTML string with badges
 */
export function createThreatIndicatorBadges(cve) {
    const indicators = [
        { key: 'cisa_kev', label: 'CISA KEV', color: 'bg-red-500' },
        { key: 'vulncheck_kev', label: 'VulnCheck KEV', color: 'bg-orange-500' },
        { key: 'exploitdb', label: 'Exploit DB', color: 'bg-yellow-500' },
        { key: 'metasploit', label: 'Metasploit', color: 'bg-green-600' },
        { key: 'nuclei', label: 'Nuclei', color: 'bg-blue-600' },
        { key: 'poc_github', label: 'GitHub PoC', color: 'bg-purple-600' }
    ];

    const badges = indicators
        .filter(indicator => cve[indicator.key])
        .map(indicator => 
            `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${indicator.color} text-white mr-1 mb-1">
                ${indicator.label}
            </span>`
        )
        .join('');
    
    return badges || '<span class="text-gray-500 text-sm italic">No Active Indicators</span>';
}

/**
 * Escape HTML to prevent XSS
 * @param {string} str - String to escape
 * @returns {string} Escaped string
 */
export function escapeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * Debounce function to limit how often a function can fire
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @returns {Function} Debounced function
 */
export function debounce(func, wait = 150) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

