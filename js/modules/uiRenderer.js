/**
 * UIRenderer Module
 * Handles all UI rendering and DOM manipulation
 */

import * as Utils from './utils.js';

export class UIRenderer {
    constructor(elements) {
        this.elements = elements;
    }

    /**
     * Display CVE results in table
     * @param {Array<Object>} results - CVE results to display
     */
    renderResults(results) {
        this.elements.resultsBody.innerHTML = '';
        
        // Update results count
        this.elements.resultsCount.textContent = `Showing ${results.length} result${results.length !== 1 ? 's' : ''}`;
        
        // Update stats
        this.updateStats(results);
        
        // Show the stats bar
        this.elements.statsBar.classList.remove('hidden');

        // Render each row
        results.forEach(cve => {
            const row = this.createResultRow(cve);
            this.elements.resultsBody.appendChild(row);
        });

        // Show results container
        this.showResults();
    }

    /**
     * Create a table row for a CVE result
     * @param {Object} cve - CVE data
     * @returns {HTMLElement} Table row element
     */
    createResultRow(cve) {
        const threatIndicatorBadges = Utils.createThreatIndicatorBadges(cve);
        
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50 transition-colors';
        row.innerHTML = this.getRowHTML(cve, threatIndicatorBadges);
        
        // Add click handler for details button
        const viewButton = row.querySelector('.view-details');
        viewButton.addEventListener('click', () => {
            if (this.onViewDetails) {
                this.onViewDetails(cve);
            }
        });
        
        return row;
    }

    /**
     * Get HTML for a result row
     * @param {Object} cve - CVE data
     * @param {string} threatIndicatorBadges - Pre-rendered threat badges HTML
     * @returns {string} HTML string
     */
    getRowHTML(cve, threatIndicatorBadges) {
        return `
            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${cve.cve}</td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2.5 py-1 rounded-lg text-sm font-medium ${Utils.getSeverityColor(cve.base_score)}">
                    ${cve.base_score || 'N/A'} (${cve.base_severity || 'N/A'})
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2.5 py-1 rounded-lg text-sm font-medium ${Utils.getSeverityColor(cve['cvss-bt_score'])}">
                    ${cve['cvss-bt_score'] || 'N/A'} (${cve['cvss-bt_severity'] || 'N/A'})
                </span>
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2.5 py-1 rounded-lg text-sm font-medium ${Utils.getSeverityColor(cve['cvss-te_score'])}">
                    ${cve['cvss-te_score'] || 'N/A'} (${cve['cvss-te_severity'] || 'N/A'})
                </span>
            </td>
            <td class="px-6 py-4">
                <div class="flex items-center">
                    <div class="epss-table-container mr-2 flex-grow">
                        <div class="epss-progress-bar ${Utils.getEpssColor(cve.epss)}" style="width: ${Math.min(cve.epss * 100, 100)}%"></div>
                    </div>
                    <span class="text-xs ${Utils.getEpssTextColor(cve.epss)}">${Utils.formatEpssPercentage(cve.epss)}</span>
                </div>
            </td>
            <td class="px-6 py-4">
                ${threatIndicatorBadges}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${Utils.formatDate(cve.published_date)}</td>
            <td class="px-6 py-4 text-center">
                <button class="view-details bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium py-1 px-3 rounded-lg transition-colors">
                    Details
                </button>
            </td>
        `;
    }

    /**
     * Update statistics bar
     * @param {Array<Object>} results - CVE results
     */
    updateStats(results) {
        this.elements.totalResults.textContent = results.length;
        this.elements.criticalCount.textContent = results.filter(cve => cve['cvss-te_severity'] === 'CRITICAL').length;
        this.elements.highCount.textContent = results.filter(cve => cve['cvss-te_severity'] === 'HIGH').length;
        document.getElementById('high-epss-count').textContent = results.filter(cve => cve.epss && cve.epss >= CONFIG.EPSS_THRESHOLDS.HIGH).length;
        this.elements.exploitCount.textContent = results.filter(cve => Utils.hasExploits(cve)).length;
    }

    /**
     * Show CVE details modal
     * @param {Object} cve - CVE data
     */
    showModal(cve) {
        this.elements.modalTitle.textContent = `${cve.cve} Details`;
        this.elements.modalContent.innerHTML = this.getModalContentHTML(cve);
        this.elements.modal.classList.remove('hidden');
        
        // Prevent background scrolling
        document.body.style.overflow = 'hidden';
    }

    /**
     * Get modal content HTML
     * @param {Object} cve - CVE data
     * @returns {string} HTML string
     */
    getModalContentHTML(cve) {
        return `
            <!-- Single-column header for basic info -->
            <div class="mb-6">
                <div class="bg-gray-50 p-4 rounded-lg border border-gray-200">
                    <h4 class="font-bold mb-3 text-lg text-gray-800">Vulnerability Details</h4>
                    <div class="grid grid-cols-3 gap-4">
                        <div>
                            <p class="text-sm text-gray-600 mb-1">Published:</p>
                            <p class="font-medium">${Utils.formatDate(cve.published_date)}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-600 mb-1">Last Modified:</p>
                            <p class="font-medium">${Utils.formatDate(cve.last_modified_date)}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-600 mb-1">Assigner:</p>
                            <p class="font-medium">${cve.assigner || 'N/A'}</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- CVSS Scores row - 3 score boxes side by side -->
            <div class="mb-6">
                <h4 class="font-bold mb-3 text-lg text-gray-800">Scoring</h4>
                <div class="grid grid-cols-3 gap-4">
                    <div class="bg-gray-50 p-3 rounded-lg border border-gray-200">
                        <p class="font-medium text-gray-700 mb-2">CVSS Base</p>
                        <span class="inline-flex items-center px-3 py-1 rounded-lg ${Utils.getSeverityColor(cve.base_score)}">
                            ${cve.base_score || 'N/A'} (${cve.base_severity || 'N/A'})
                        </span>
                    </div>
                    <div class="bg-gray-50 p-3 rounded-lg border border-gray-200">
                        <p class="font-medium text-gray-700 mb-2">CVSS-BT (Temporal)</p>
                        <span class="inline-flex items-center px-3 py-1 rounded-lg ${Utils.getSeverityColor(cve['cvss-bt_score'])}">
                            ${cve['cvss-bt_score'] || 'N/A'} (${cve['cvss-bt_severity'] || 'N/A'})
                        </span>
                    </div>
                    <div class="bg-gray-50 p-3 rounded-lg border border-gray-200">
                        <p class="font-medium text-gray-700 mb-2">CVSS-TE (Enhanced)</p>
                        <span class="inline-flex items-center px-3 py-1 rounded-lg ${Utils.getSeverityColor(cve['cvss-te_score'])}">
                            ${cve['cvss-te_score'] || 'N/A'} (${cve['cvss-te_severity'] || 'N/A'})
                        </span>
                    </div>
                </div>
            </div>
            
            <!-- EPSS Score -->
            <div class="mb-6">
                <div class="bg-gray-50 p-4 rounded-lg border border-gray-200">
                    <h4 class="font-medium text-gray-700 mb-2">EPSS Score</h4>
                    <div class="flex items-center mb-2">
                        <div class="epss-progress-container mr-2 flex-grow">
                            <div class="epss-progress-bar ${Utils.getEpssColor(cve.epss)}" style="width: ${Math.min(cve.epss * 100, 100)}%"></div>
                        </div>
                        <span class="text-sm ${Utils.getEpssTextColor(cve.epss)} ml-2 w-16 text-right">${Utils.formatEpssPercentage(cve.epss)}</span>
                    </div>
                    <p class="text-xs text-gray-500">Exploit Prediction Scoring System - likelihood of exploitation</p>
                </div>
            </div>

            <!-- Two-column layout for vectors and threat intel -->
            <div class="grid grid-cols-2 gap-6">
                <div>
                    <h4 class="font-bold mb-3 text-lg text-gray-800">CVSS Vectors</h4>
                    <div class="mb-3">
                        <p class="text-sm text-gray-600 mb-1">Base Vector:</p>
                        <p class="bg-gray-50 p-2 rounded-lg text-sm font-mono border border-gray-200">${cve.base_vector || "N/A"}</p>
                    </div>
                    <div>
                        <p class="text-sm text-gray-600 mb-1">CVSS-BT Vector:</p>
                        <p class="bg-gray-50 p-2 rounded-lg text-sm font-mono border border-gray-200">${cve['cvss-bt_vector'] || "N/A"}</p>
                    </div>
                </div>
                <div>
                    <h4 class="font-bold mb-3 text-lg text-gray-800">Threat Intelligence</h4>
                    <div class="bg-gray-50 p-3 rounded-lg border border-gray-200 mb-4">
                        <p class="font-medium text-gray-700 mb-2">Indicators:</p>
                        <div>${Utils.createThreatIndicatorBadges(cve)}</div>
                    </div>
                    
                    <div class="bg-gray-50 p-3 rounded-lg border border-gray-200">
                        <h4 class="font-medium text-gray-700 mb-2">Exploit Quality</h4>
                        <div class="grid grid-cols-2 gap-2 text-sm">
                            <p><span class="font-medium">Quality Score:</span> ${(cve.quality_score * 100).toFixed(1)}%</p>
                            <p><span class="font-medium">Exploit Sources:</span> ${cve.exploit_sources}</p>
                            <p><span class="font-medium">Reliability:</span> ${(cve.reliability * 100).toFixed(0)}%</p>
                            <p><span class="font-medium">Ease of Use:</span> ${(cve.ease_of_use * 100).toFixed(0)}%</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- References -->
            <div class="mt-6">
                <h4 class="font-bold mb-3 text-lg text-gray-800">References</h4>
                <div class="bg-gray-50 p-4 rounded-lg border border-gray-200">
                    <a href="https://nvd.nist.gov/vuln/detail/${cve.cve}" target="_blank" class="text-blue-600 hover:text-blue-800 hover:underline block mb-2">
                        NIST NVD Database: ${cve.cve}
                    </a>
                    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.cve}" target="_blank" class="text-blue-600 hover:text-blue-800 hover:underline block">
                        Mitre CVE: ${cve.cve}
                    </a>
                </div>
            </div>
        `;
    }

    /**
     * Close modal
     */
    closeModal() {
        this.elements.modal.classList.add('hidden');
        document.body.style.overflow = '';
    }

    /**
     * Show error message
     * @param {string} message - Error message
     */
    showError(message) {
        this.elements.errorDiv.classList.remove('hidden');
        document.getElementById('error-message').textContent = message;
    }

    /**
     * Hide error message
     */
    hideError() {
        this.elements.errorDiv.classList.add('hidden');
    }

    /**
     * Show loading indicator
     */
    showLoading() {
        this.elements.loadingIndicator.classList.remove('hidden');
    }

    /**
     * Hide loading indicator
     */
    hideLoading() {
        this.elements.loadingIndicator.classList.add('hidden');
    }

    /**
     * Show results container
     */
    showResults() {
        this.elements.resultsContainer.classList.remove('hidden');
    }

    /**
     * Hide results container
     */
    hideResults() {
        this.elements.resultsContainer.classList.add('hidden');
    }

    /**
     * Display recent searches
     * @param {Array<string>} searches - Recent searches
     * @param {Function} onSearchClick - Callback when search is clicked
     */
    displayRecentSearches(searches, onSearchClick) {
        if (searches.length === 0) return;

        const recentSearchesHtml = `
            <div class="mt-4">
                <p class="text-sm text-gray-600">Recent Searches:</p>
                <div class="flex flex-wrap gap-2 mt-1">
                    ${searches.map(search => `
                        <button class="recent-search-btn text-xs bg-gray-100 hover:bg-gray-200 text-gray-700 px-2 py-1 rounded-full transition-colors">
                            ${search}
                        </button>
                    `).join('')}
                </div>
            </div>
        `;

        // Add after the search input
        const searchInput = document.querySelector('#cve-input');
        const existingRecentSearches = document.querySelector('.recent-searches');
        if (existingRecentSearches) {
            existingRecentSearches.remove();
        }
        
        const recentSearchesDiv = document.createElement('div');
        recentSearchesDiv.className = 'recent-searches';
        recentSearchesDiv.innerHTML = recentSearchesHtml;
        searchInput.insertAdjacentElement('afterend', recentSearchesDiv);

        // Add click handlers
        recentSearchesDiv.querySelectorAll('.recent-search-btn').forEach(button => {
            button.addEventListener('click', () => {
                if (onSearchClick) {
                    onSearchClick(button.textContent.trim());
                }
            });
        });
    }

    /**
     * Set callback for view details
     * @param {Function} callback - Callback function
     */
    setOnViewDetails(callback) {
        this.onViewDetails = callback;
    }
}

