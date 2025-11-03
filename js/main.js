/**
 * CVSS-TE Main Application
 * Enhanced vulnerability scoring system
 */

document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const cveInput = document.getElementById('cve-input');
    const searchBtn = document.getElementById('search-btn');
    const exportBtn = document.getElementById('export-btn');
    const severityFilter = document.getElementById('severity-filter');
    const sortBy = document.getElementById('sort-by');
    const loadingIndicator = document.getElementById('loading');
    const errorDiv = document.getElementById('error');
    const resultsContainer = document.getElementById('results-container');
    const resultsBody = document.getElementById('results-body');
    const resultsCount = document.getElementById('results-count');
    const statsBar = document.getElementById('stats-bar');
    const totalResults = document.getElementById('total-results');
    const criticalCount = document.getElementById('critical-count');
    const highCount = document.getElementById('high-count');
    const exploitCount = document.getElementById('exploit-count');
    const modal = document.getElementById('cve-detail-modal');
    const closeModal = document.getElementById('close-modal');
    const closeModalBtn = document.getElementById('close-modal-btn');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const lastUpdateTime = document.getElementById('last-update-time');

    let csvData = null;
    let currentResults = [];

    // Analytics tracking functions
    function trackSearch(searchTerm, resultsCount) {
        if (typeof gtag === 'function') {
            gtag('event', 'search', {
                'search_term': searchTerm,
                'results_count': resultsCount
            });
        }
    }
    
    function trackExport(count) {
        if (typeof gtag === 'function') {
            gtag('event', 'export', {
                'items_count': count
            });
        }
    }
    
    function trackCveView(cveId, severity) {
        if (typeof gtag === 'function') {
            gtag('event', 'view_cve_details', {
                'cve_id': cveId,
                'severity': severity
            });
        }
    }
    
    function trackFilterChange(filterType, value) {
        if (typeof gtag === 'function') {
            gtag('event', 'filter_change', {
                'filter_type': filterType,
                'filter_value': value
            });
        }
    }
    
    function trackSortChange(value) {
        if (typeof gtag === 'function') {
            gtag('event', 'sort_change', {
                'sort_value': value
            });
        }
    }

    // Helper function for EPSS display
    function formatEpssPercentage(epssValue) {
        if (epssValue === null || epssValue === undefined) return '0.00%';
        const value = parseFloat(epssValue);
        if (isNaN(value)) return '0.00%';
        return (value * 100).toFixed(2) + '%';
    }

    // Fetch the last run time
    fetch(CONFIG.LAST_RUN_PATH)
        .then(response => response.text())
        .then(text => {
            const lastRunDate = new Date(text.trim());
            
            // Format for UTC display with more explicit options
            const utcOptions = { 
                year: 'numeric', 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                timeZone: 'UTC' 
            };
            const utcTime = lastRunDate.toLocaleString('en-US', utcOptions) + ' UTC';
            
            // Format for local display with explicit timezone
            const localOptions = { 
                year: 'numeric', 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                timeZoneName: 'short'
            };
            const localTime = lastRunDate.toLocaleString('en-US', localOptions);
            
            lastUpdateTime.textContent = `Last Updated: ${utcTime} / ${localTime}`;
        })
        .catch(error => {
            console.error('Error fetching last run time:', error);
            lastUpdateTime.textContent = 'Last Updated: Unknown';
        });

    // Helper Functions
    function formatDate(dateString) {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleDateString('en-US', { 
            year: 'numeric', 
            month: 'short', 
            day: 'numeric' 
        });
    }

    // Recent searches functionality
    function saveRecentSearch(cveList) {
        const recentSearches = JSON.parse(localStorage.getItem('recentSearches') || '[]');
        recentSearches.unshift(cveList);
        if (recentSearches.length > CONFIG.MAX_RECENT_SEARCHES) recentSearches.pop();
        localStorage.setItem('recentSearches', JSON.stringify(recentSearches));
        displayRecentSearches();
    }

    function displayRecentSearches() {
        const recentSearches = JSON.parse(localStorage.getItem('recentSearches') || '[]');
        if (recentSearches.length === 0) return;

        const recentSearchesHtml = `
            <div class="mt-4">
                <p class="text-sm text-gray-600">Recent Searches:</p>
                <div class="flex flex-wrap gap-2 mt-1">
                    ${recentSearches.map(search => `
                        <button class="text-xs bg-gray-100 hover:bg-gray-200 text-gray-700 px-2 py-1 rounded-full transition-colors">
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

        // Add click handlers to recent search buttons
        recentSearchesDiv.querySelectorAll('button').forEach(button => {
            button.addEventListener('click', () => {
                cveInput.value = button.textContent.trim();
                searchBtn.click();
            });
        });
    }

    function getSeverityColor(score) {
        if (!score) return 'bg-gray-400 text-white';
        const numScore = parseFloat(score);
        if (numScore >= CONFIG.CVSS_THRESHOLDS.CRITICAL) return 'bg-red-600 text-white';
        if (numScore >= CONFIG.CVSS_THRESHOLDS.HIGH) return 'bg-orange-600 text-white';
        if (numScore >= CONFIG.CVSS_THRESHOLDS.MEDIUM) return 'bg-yellow-500 text-black';
        return 'bg-green-600 text-white';
    }
    
    // Function for progress bar coloring
    function getEpssColor(epssScore) {
        if (!epssScore && epssScore !== 0) return 'epss-unknown';
        const score = parseFloat(epssScore);
        if (score >= CONFIG.EPSS_THRESHOLDS.CRITICAL) return 'epss-critical'; // Critical (50%+)
        if (score >= CONFIG.EPSS_THRESHOLDS.HIGH) return 'epss-high';    // High (36%+) - EPSS threshold from README
        if (score >= CONFIG.EPSS_THRESHOLDS.MEDIUM) return 'epss-medium';   // Medium (10-36%)
        return 'epss-low';                        // Low (<10%)
    }
    
    // Function for text coloring (separate from progress bar)
    function getEpssTextColor(epssScore) {
        if (!epssScore && epssScore !== 0) return 'epss-text-unknown';
        const score = parseFloat(epssScore);
        if (score >= CONFIG.EPSS_THRESHOLDS.CRITICAL) return 'epss-text-critical';   // Critical
        if (score >= CONFIG.EPSS_THRESHOLDS.HIGH) return 'epss-text-high';      // High
        if (score >= CONFIG.EPSS_THRESHOLDS.MEDIUM) return 'epss-text-medium';     // Medium
        return 'epss-text-low';                          // Low
    }

    function hasExploits(cve) {
        // Check if any of these are truthy (1 instead of true)
        return cve.exploitdb || cve.metasploit || cve.nuclei || cve.poc_github;
    }

    function createThreatIndicatorBadges(cve) {
        const indicators = [
            { key: 'cisa_kev', label: 'CISA KEV', color: 'bg-red-500' },
            { key: 'vulncheck_kev', label: 'VulnCheck KEV', color: 'bg-orange-500' },
            { key: 'exploitdb', label: 'Exploit DB', color: 'bg-yellow-500' },
            { key: 'metasploit', label: 'Metasploit', color: 'bg-green-600' },
            { key: 'nuclei', label: 'Nuclei', color: 'bg-blue-600' },
            { key: 'poc_github', label: 'GitHub PoC', color: 'bg-purple-600' }
        ];

        const badges = indicators
            // Filter based on truthy values (1) rather than strictly === true
            .filter(indicator => cve[indicator.key])
            .map(indicator => 
                `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${indicator.color} text-white mr-1 mb-1">
                    ${indicator.label}
                </span>`
            )
            .join('');
        
        return badges || '<span class="text-gray-500 text-sm italic">No Active Indicators</span>';
    }

    function showCVEDetails(cve) {
        modalTitle.textContent = `${cve.cve} Details`;
        
        const content = `
            <!-- Single-column header for basic info -->
            <div class="mb-6">
                <div class="bg-gray-50 p-4 rounded-lg border border-gray-200">
                    <h4 class="font-bold mb-3 text-lg text-gray-800">Vulnerability Details</h4>
                    <div class="grid grid-cols-3 gap-4">
                        <div>
                            <p class="text-sm text-gray-600 mb-1">Published:</p>
                            <p class="font-medium">${formatDate(cve.published_date)}</p>
                        </div>
                        <div>
                            <p class="text-sm text-gray-600 mb-1">Last Modified:</p>
                            <p class="font-medium">${formatDate(cve.last_modified_date)}</p>
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
                        <span class="inline-flex items-center px-3 py-1 rounded-lg ${getSeverityColor(cve.base_score)}">
                            ${cve.base_score || 'N/A'} (${cve.base_severity || 'N/A'})
                        </span>
                    </div>
                    <div class="bg-gray-50 p-3 rounded-lg border border-gray-200">
                        <p class="font-medium text-gray-700 mb-2">CVSS-BT (Temporal)</p>
                        <span class="inline-flex items-center px-3 py-1 rounded-lg ${getSeverityColor(cve['cvss-bt_score'])}">
                            ${cve['cvss-bt_score'] || 'N/A'} (${cve['cvss-bt_severity'] || 'N/A'})
                        </span>
                    </div>
                    <div class="bg-gray-50 p-3 rounded-lg border border-gray-200">
                        <p class="font-medium text-gray-700 mb-2">CVSS-TE (Enhanced)</p>
                        <span class="inline-flex items-center px-3 py-1 rounded-lg ${getSeverityColor(cve['cvss-te_score'])}">
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
                            <div class="epss-progress-bar ${getEpssColor(cve.epss)}" style="width: ${Math.min(cve.epss * 100, 100)}%"></div>
                        </div>
                        <span class="text-sm ${getEpssTextColor(cve.epss)} ml-2 w-16 text-right">${formatEpssPercentage(cve.epss)}</span>
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
                        <div>${createThreatIndicatorBadges(cve)}</div>
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
        
        modalContent.innerHTML = content;
        modal.classList.remove('hidden');
        
        // Track modal view in analytics
        trackCveView(cve.cve, cve['cvss-te_severity']);
        
        // Prevent background scrolling
        document.body.style.overflow = 'hidden';
    }

    function closeDetailModal() {
        modal.classList.add('hidden');
        // Restore background scrolling
        document.body.style.overflow = '';
    }

    function displayCVEResults(results) {
        resultsBody.innerHTML = '';
        currentResults = results;
        
        // Update results count
        resultsCount.textContent = `Showing ${results.length} result${results.length !== 1 ? 's' : ''}`;
        
        // Update stats
        totalResults.textContent = results.length;
        criticalCount.textContent = results.filter(cve => cve['cvss-te_severity'] === 'CRITICAL').length;
        highCount.textContent = results.filter(cve => cve['cvss-te_severity'] === 'HIGH').length;
        document.getElementById('high-epss-count').textContent = results.filter(cve => cve.epss && cve.epss >= CONFIG.EPSS_THRESHOLDS.HIGH).length;
        exploitCount.textContent = results.filter(cve => hasExploits(cve)).length;
        
        // Show the stats bar
        statsBar.classList.remove('hidden');

        results.forEach(cve => {
            const threatIndicatorBadges = createThreatIndicatorBadges(cve);
            
            const row = document.createElement('tr');
            row.className = 'hover:bg-gray-50 transition-colors';
            
            row.innerHTML = `
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${cve.cve}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2.5 py-1 rounded-lg text-sm font-medium ${getSeverityColor(cve.base_score)}">
                        ${cve.base_score || 'N/A'} (${cve.base_severity || 'N/A'})
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2.5 py-1 rounded-lg text-sm font-medium ${getSeverityColor(cve['cvss-bt_score'])}">
                        ${cve['cvss-bt_score'] || 'N/A'} (${cve['cvss-bt_severity'] || 'N/A'})
                    </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <span class="px-2.5 py-1 rounded-lg text-sm font-medium ${getSeverityColor(cve['cvss-te_score'])}">
                        ${cve['cvss-te_score'] || 'N/A'} (${cve['cvss-te_severity'] || 'N/A'})
                    </span>
                </td>
                <td class="px-6 py-4">
                    <div class="flex items-center">
                        <div class="epss-table-container mr-2 flex-grow">
                            <div class="epss-progress-bar ${getEpssColor(cve.epss)}" style="width: ${Math.min(cve.epss * 100, 100)}%"></div>
                        </div>
                        <span class="text-xs ${getEpssTextColor(cve.epss)}">${formatEpssPercentage(cve.epss)}</span>
                    </div>
                </td>
                <td class="px-6 py-4">
                    ${threatIndicatorBadges}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-700">${formatDate(cve.published_date)}</td>
                <td class="px-6 py-4 text-center">
                    <button class="view-details bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium py-1 px-3 rounded-lg transition-colors">
                        Details
                    </button>
                </td>
            `;
            
            const viewButton = row.querySelector('.view-details');
            viewButton.addEventListener('click', () => showCVEDetails(cve));
            
            resultsBody.appendChild(row);
        });

        resultsContainer.classList.remove('hidden');
    }

    function filterAndSortResults(results) {
        const severityFilterValue = severityFilter.value;
        const sortByValue = sortBy.value;

        let filteredResults = [...results];

        // Apply severity filter
        if (severityFilterValue) {
            filteredResults = filteredResults.filter(cve => 
                cve['cvss-te_severity'] === severityFilterValue
            );
        }

        // Apply sorting
        switch(sortByValue) {
            case 'published_date_desc':
                filteredResults.sort((a, b) => new Date(b.published_date || 0) - new Date(a.published_date || 0));
                break;
            case 'published_date_asc':
                filteredResults.sort((a, b) => new Date(a.published_date || 0) - new Date(b.published_date || 0));
                break;
            case 'base_score_desc':
                filteredResults.sort((a, b) => (parseFloat(b.base_score) || 0) - (parseFloat(a.base_score) || 0));
                break;
            case 'base_score_asc':
                filteredResults.sort((a, b) => (parseFloat(a.base_score) || 0) - (parseFloat(b.base_score) || 0));
                break;
            case 'cvss-bt_score_desc':
                filteredResults.sort((a, b) => (parseFloat(b['cvss-bt_score']) || 0) - (parseFloat(a['cvss-bt_score']) || 0));
                break;
            case 'cvss-bt_score_asc':
                filteredResults.sort((a, b) => (parseFloat(a['cvss-bt_score']) || 0) - (parseFloat(b['cvss-bt_score']) || 0));
                break;
            case 'cvss-te_score_desc':
                filteredResults.sort((a, b) => (parseFloat(b['cvss-te_score']) || 0) - (parseFloat(a['cvss-te_score']) || 0));
                break;
            case 'epss_desc':
                filteredResults.sort((a, b) => (parseFloat(b.epss) || 0) - (parseFloat(a.epss) || 0));
                break;
        }

        return filteredResults;
    }

    // Load data immediately
    loadingIndicator.classList.remove('hidden');
    
    // Fetch the CSV file (from the root directory for GitHub Pages)
    fetch(CONFIG.CSV_PATH)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! Status: ${response.status}`);
            }
            return response.text();
        })
        .then(csvText => {
            // Parse CSV
            const parseResult = Papa.parse(csvText, {
                header: true,
                dynamicTyping: true,
                skipEmptyLines: true
            });
            
            if (parseResult.errors && parseResult.errors.length > 0) {
                console.warn('CSV parsing warnings:', parseResult.errors);
            }
            
            csvData = parseResult.data;

            // Fix any potential data issues
            csvData = csvData.filter(row => row && row.cve && row.cve.startsWith('CVE-'));
            
            // Track data loaded event
            if (typeof gtag === 'function') {
                gtag('event', 'data_loaded', {
                    'cve_count': csvData.length
                });
            }
            
            // Hide loading indicator
            loadingIndicator.classList.add('hidden');
            console.log(`Loaded ${csvData.length} CVE records successfully`);
        })
        .catch(error => {
            console.error('Error loading CSV:', error);
            loadingIndicator.classList.add('hidden');
            errorDiv.classList.remove('hidden');
            document.getElementById('error-message').textContent = 'Error loading CVE data: ' + error.message;
        });

    // Event Listeners
    // Search button event listener
    searchBtn.addEventListener('click', function() {
        // Reset previous results and errors
        errorDiv.classList.add('hidden');
        resultsContainer.classList.add('hidden');
        
        // Get and process CVE input
        const inputText = cveInput.value.trim();
        
        if (!inputText) {
            errorDiv.classList.remove('hidden');
            document.getElementById('error-message').textContent = 'Please enter valid CVE(s)';
            return;
        }
        
        const inputCVEs = inputText.split(',')
            .map(cve => {
                cve = cve.trim().toUpperCase();
                // Add CVE- prefix if missing
                if (cve.match(/^\d{4}-\d+$/)) {
                    return 'CVE-' + cve;
                }
                return cve;
            })
            .filter(cve => cve.match(/^CVE-\d{4}-\d+$/));

        if (inputCVEs.length === 0) {
            errorDiv.classList.remove('hidden');
            document.getElementById('error-message').textContent = 'Please enter valid CVE(s)';
            return;
        }

        // If CSV is not loaded
        if (!csvData || csvData.length === 0) {
            errorDiv.classList.remove('hidden');
            document.getElementById('error-message').textContent = 'CVE data not loaded. Please reload the page and try again.';
            return;
        }

        // Find matching CVEs
        const matchedCVEs = [];
        
        inputCVEs.forEach(cve => {
            const match = csvData.find(row => row && row.cve === cve);
            if (match) {
                matchedCVEs.push(match);
            }
        });

        // Handle no matches
        if (matchedCVEs.length === 0) {
            errorDiv.classList.remove('hidden');
            document.getElementById('error-message').textContent = 'No matching CVEs found';
            return;
        }

        // Apply current filters and sorting
        const filteredAndSorted = filterAndSortResults(matchedCVEs);
        
        // Track search analytics
        trackSearch(inputText, matchedCVEs.length);
        
        // Save recent search
        saveRecentSearch(inputText);
        
        // Display matched CVEs
        displayCVEResults(filteredAndSorted);
    });

    // Export button event listener
    exportBtn.addEventListener('click', function() {
        if (currentResults.length === 0) {
            alert('No results to export');
            return;
        }

        // Create CSV content
        const headers = ['CVE', 'Base Score', 'Base Severity', 'CVSS-BT Score', 'CVSS-BT Severity', 'CVSS-TE Score', 'CVSS-TE Severity', 'EPSS Score', 'CVSS-BT Vector', 'Published Date'];
        const csvContent = [
            headers.join(','),
            ...currentResults.map(cve => 
                [
                    cve.cve, 
                    cve.base_score, 
                    cve.base_severity,
                    cve['cvss-bt_score'],
                    cve['cvss-bt_severity'],
                    cve['cvss-te_score'], 
                    cve['cvss-te_severity'],
                    cve.epss ? (cve.epss * 100).toFixed(2) + '%' : '0%',
                    `"${(cve['cvss-bt_vector'] || '').replace(/"/g, '""')}"`,
                    cve.published_date
                ].join(',')
            )
        ].join('\n');

        // Track export analytics
        trackExport(currentResults.length);

        // Create and trigger download
        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', 'cvss-te-results.csv');
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    });

    // Filter and sort event listeners
    severityFilter.addEventListener('change', function() {
        trackFilterChange('severity', this.value);
        
        if (currentResults.length > 0) {
            const filtered = filterAndSortResults(currentResults);
            displayCVEResults(filtered);
        }
    });

    sortBy.addEventListener('change', function() {
        trackSortChange(this.value);
        
        if (currentResults.length > 0) {
            const filtered = filterAndSortResults(currentResults);
            displayCVEResults(filtered);
        }
    });

    // Modal close button events
    closeModal.addEventListener('click', closeDetailModal);
    closeModalBtn.addEventListener('click', closeDetailModal);
    
    // Close modal when clicking outside content
    modal.addEventListener('click', function(event) {
        if (event.target === modal) {
            closeDetailModal();
        }
    });
    
    // Close modal on escape key
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape' && !modal.classList.contains('hidden')) {
            closeDetailModal();
        }
    });

    // Keyboard shortcut for search (Enter in the search box)
    cveInput.addEventListener('keydown', function(event) {
        if (event.key === 'Enter') {
            searchBtn.click();
        }
    });

    // Scoring info panel controls
    const scoringInfoPanel = document.getElementById('scoring-info-panel');
    const showScoringInfoBtn = document.getElementById('show-scoring-info');
    const closeInfoPanelBtn = document.getElementById('close-info-panel');

    showScoringInfoBtn.addEventListener('click', function() {
        scoringInfoPanel.classList.remove('hidden');
        // Track info panel view
        if (typeof gtag === 'function') {
            gtag('event', 'view_info_panel');
        }
        // Smooth scroll to the panel
        scoringInfoPanel.scrollIntoView({ behavior: 'smooth' });
    });

    closeInfoPanelBtn.addEventListener('click', function() {
        scoringInfoPanel.classList.add('hidden');
    });

    // Remove the automatic display on first search
    let firstSearchDone = false;
    searchBtn.addEventListener('click', function() {
        if (!firstSearchDone && currentResults.length > 0) {
            firstSearchDone = true;
        }
    });
});

