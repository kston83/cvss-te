/**
 * DashboardUIRenderer Module
 * Handles rendering of dashboard components
 */

import * as Utils from './utils.js';

export class DashboardUIRenderer {
    constructor(analytics = null) {
        // Element references set in init()
        this.analytics = analytics;
    }

    /**
     * Initialize renderer with DOM elements
     */
    init() {
        this.elements = {
            loading: document.getElementById('dashboard-loading'),
            content: document.getElementById('dashboard-content'),
            // Statistics
            statTotal: document.getElementById('stat-total'),
            statKev: document.getElementById('stat-kev'),
            statCritical: document.getElementById('stat-critical'),
            statHigh: document.getElementById('stat-high'),
            statEpss: document.getElementById('stat-epss'),
            statExploits: document.getElementById('stat-exploits'),
            // Lists
            kevList: document.getElementById('kev-list'),
            recentList: document.getElementById('recent-list'),
            emergingList: document.getElementById('emerging-list'),
            // Filters
            recentDaysFilter: document.getElementById('recent-days-filter'),
            emergingDaysFilter: document.getElementById('emerging-days-filter')
        };
    }

    /**
     * Show dashboard content, hide loading
     */
    showContent() {
        this.elements.loading.classList.add('hidden');
        this.elements.content.classList.remove('hidden');
    }

    /**
     * Render statistics cards
     * @param {Object} stats - Statistics object
     */
    renderStatistics(stats) {
        this.elements.statTotal.textContent = stats.totalCves.toLocaleString();
        this.elements.statKev.textContent = stats.cisaKevs.toLocaleString();
        this.elements.statCritical.textContent = stats.criticalCves.toLocaleString();
        this.elements.statHigh.textContent = stats.highCves.toLocaleString();
        this.elements.statEpss.textContent = stats.highEpss.toLocaleString();
        this.elements.statExploits.textContent = stats.withExploits.toLocaleString();
    }

    /**
     * Render CVE card (compact version for lists)
     * @param {Object} cve - CVE data
     * @param {string} source - Source section (e.g., "cisa_kevs", "recent_cves", "emerging_threats")
     * @returns {HTMLElement} Card element
     */
    renderCveCard(cve, source = 'unknown') {
        const card = document.createElement('div');
        card.className = 'border border-gray-200 rounded-lg p-4 cursor-pointer bg-gray-50 hover:bg-gray-100 hover:shadow-md transition-all duration-200';
        
        // Truncate description if available
        const description = cve.description ? 
            (cve.description.length > 150 ? cve.description.substring(0, 150) + '...' : cve.description) : '';
        
        card.innerHTML = `
            <div class="flex items-start justify-between gap-3">
                <div class="flex-1 min-w-0">
                    <!-- CVE ID and Scores -->
                    <div class="flex items-center gap-2 mb-2 flex-wrap">
                        <span class="font-mono font-bold text-blue-600">${cve.cve}</span>
                        
                        <!-- CVSS-TE Score (Primary) -->
                        <div class="flex items-center gap-1">
                            <span class="text-xs text-gray-500 font-medium">CVSS-TE:</span>
                            <span class="px-2 py-1 rounded text-xs font-semibold ${Utils.getSeverityColor(cve['cvss-te_score'])}">
                                ${cve['cvss-te_score'] || 'N/A'} ${cve['cvss-te_severity'] || ''}
                            </span>
                        </div>
                        
                        <!-- Base Score (Comparison) -->
                        ${cve.base_score ? `
                            <div class="flex items-center gap-1">
                                <span class="text-xs text-gray-400 font-medium">Base:</span>
                                <span class="px-2 py-0.5 rounded text-xs font-medium bg-gray-200 text-gray-700">
                                    ${cve.base_score}
                                </span>
                            </div>
                        ` : ''}
                        
                        <!-- KEV Badge -->
                        ${(cve.cisa_kev === 1 || cve.cisa_kev === true || cve.cisa_kev === '1') ? 
                            '<span class="px-2 py-1 rounded text-xs font-semibold bg-red-500 text-white">🚨 KEV</span>' : ''}
                    </div>
                    
                    <!-- Description -->
                    ${description ? `
                        <p class="text-sm text-gray-700 mb-2 line-clamp-2">${description}</p>
                    ` : ''}
                    
                    <!-- Metadata Row -->
                    <div class="flex items-center gap-4 text-sm text-gray-600 mb-2 flex-wrap">
                        ${cve.cisa_kev_date_added ? `<span class="font-medium text-red-600">🚨 KEV Added: ${Utils.formatDate(cve.cisa_kev_date_added)}</span>` : ''}
                        ${cve.published_date ? `<span>📅 Published: ${Utils.formatDate(cve.published_date)}</span>` : ''}
                        ${cve.epss ? `<span>📈 EPSS: ${Utils.formatEpssPercentage(cve.epss)}</span>` : ''}
                        ${cve.vendor_project ? `<span>🏢 ${cve.vendor_project}</span>` : ''}
                    </div>
                    
                    <!-- Threat Badges -->
                    ${this.renderThreatBadges(cve)}
                </div>
                
                <!-- View Button -->
                <button class="text-blue-600 hover:text-blue-700 text-sm font-semibold transition-colors flex-shrink-0">
                    View →
                </button>
            </div>
        `;
        
        // Click to navigate to lookup page with CVE pre-filled
        card.addEventListener('click', () => {
            // Track CVE card click
            if (this.analytics) {
                this.analytics.trackCVECardClick(
                    cve.cve,
                    source,
                    cve['cvss-te_severity'] || 'Unknown'
                );
                this.analytics.trackNavigation('dashboard', 'lookup', 'cve_card');
            }
            window.location.href = `lookup.html?cve=${cve.cve}`;
        });
        
        return card;
    }

    /**
     * Render threat indicator badges (compact)
     * @param {Object} cve - CVE data
     * @returns {string} HTML string
     */
    renderThreatBadges(cve) {
        const badges = [];
        if (cve.exploitdb) badges.push('<span class="text-xs bg-yellow-100 text-yellow-800 px-2 py-0.5 rounded">ExploitDB</span>');
        if (cve.metasploit) badges.push('<span class="text-xs bg-green-100 text-green-800 px-2 py-0.5 rounded">Metasploit</span>');
        if (cve.nuclei) badges.push('<span class="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded">Nuclei</span>');
        if (cve.poc_github) badges.push('<span class="text-xs bg-purple-100 text-purple-800 px-2 py-0.5 rounded">GitHub PoC</span>');
        
        return badges.length ? `<div class="flex gap-1 mt-2 flex-wrap">${badges.join('')}</div>` : '';
    }

    /**
     * Render list of CVEs
     * @param {Array} cves - Array of CVE objects
     * @param {HTMLElement} container - Container element
     * @param {string} source - Source section identifier
     */
    renderCveList(cves, container, source = 'unknown') {
        container.innerHTML = '';
        
        if (cves.length === 0) {
            container.innerHTML = '<p class="text-gray-500 text-center py-4">No CVEs found</p>';
            return;
        }
        
        const fragment = document.createDocumentFragment();
        cves.forEach(cve => {
            fragment.appendChild(this.renderCveCard(cve, source));
        });
        container.appendChild(fragment);
    }

    /**
     * Render CISA KEVs
     * @param {Array} kevs - Array of KEV CVEs
     */
    renderKevs(kevs) {
        this.renderCveList(kevs, this.elements.kevList, 'cisa_kevs');
    }

    /**
     * Render recent CVEs
     * @param {Array} cves - Array of recent CVEs
     */
    renderRecent(cves) {
        this.renderCveList(cves, this.elements.recentList, 'recent_cves');
    }

    /**
     * Render emerging threats
     * @param {Array} cves - Array of emerging threat CVEs
     */
    renderEmerging(cves) {
        this.renderCveList(cves, this.elements.emergingList, 'emerging_threats');
    }
}

