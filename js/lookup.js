/**
 * CVSS-TE Main Application
 * Enhanced vulnerability scoring system
 */

import { DataManager } from './modules/dataManager.js';
import { SearchEngine } from './modules/searchEngine.js';
import { Analytics } from './modules/analytics.js';
import { UIRenderer } from './modules/uiRenderer.js';
import { ExportManager } from './modules/exportManager.js';
import * as Utils from './modules/utils.js';

/**
 * Main CVSS-TE Application Class
 * Coordinates all modules and handles application logic
 */
class CVSSApp {
    constructor() {
        // Initialize DOM elements
        this.elements = {
            cveInput: document.getElementById('cve-input'),
            searchBtn: document.getElementById('search-btn'),
            exportBtn: document.getElementById('export-btn'),
            severityFilter: document.getElementById('severity-filter'),
            sortBy: document.getElementById('sort-by'),
            loadingIndicator: document.getElementById('loading'),
            errorDiv: document.getElementById('error'),
            resultsContainer: document.getElementById('results-container'),
            resultsBody: document.getElementById('results-body'),
            resultsCount: document.getElementById('results-count'),
            statsBar: document.getElementById('stats-bar'),
            totalResults: document.getElementById('total-results'),
            criticalCount: document.getElementById('critical-count'),
            highCount: document.getElementById('high-count'),
            exploitCount: document.getElementById('exploit-count'),
            modal: document.getElementById('cve-detail-modal'),
            closeModal: document.getElementById('close-modal'),
            closeModalBtn: document.getElementById('close-modal-btn'),
            modalTitle: document.getElementById('modal-title'),
            modalContent: document.getElementById('modal-content'),
            lastUpdateTime: document.getElementById('last-update-time')
        };

        // Initialize modules
        this.dataManager = new DataManager(CONFIG.CSV_PATH);
        this.searchEngine = new SearchEngine(this.dataManager);
        this.analytics = new Analytics();
        this.uiRenderer = new UIRenderer(this.elements);
        this.exportManager = new ExportManager();

        // State management
        this.originalSearchResults = [];
        this.currentResults = [];
        this.firstSearchDone = false;

        // Initialize
        this.init();
    }

    /**
     * Initialize the application
     */
    async init() {
        // Set up UI renderer callback
        this.uiRenderer.setOnViewDetails((cve) => this.showCVEDetails(cve));

        // DON'T load data immediately - lazy load on first search for better performance
        // await this.loadInitialData();

        // Fetch last update time
        this.fetchLastUpdateTime();

        // Set up event listeners
        this.setupEventListeners();

        // Display recent searches
        this.displayRecentSearches();

        // Check for CVE in URL parameters
        this.checkUrlParameters();
    }

    /**
     * Ensure CSV data is loaded (lazy loading)
     * @returns {Promise<boolean>} True if data is loaded successfully
     */
    async ensureDataLoaded() {
        if (this.dataManager.isLoaded()) {
            return true;
        }

        this.uiRenderer.showLoading();

        try {
            await this.dataManager.loadData();
            this.uiRenderer.hideLoading();
            return true;
        } catch (error) {
            console.error('Error loading CSV:', error);
            this.uiRenderer.hideLoading();
            this.uiRenderer.showError('Error loading CVE data: ' + error.message);
            return false;
        }
    }

    /**
     * Fetch and display last update time
     */
    fetchLastUpdateTime() {
        fetch(CONFIG.LAST_RUN_PATH)
            .then(response => response.text())
            .then(text => {
                const lastRunDate = new Date(text.trim());
                
                // Format for UTC display
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
                
                // Format for local display
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
                
                this.elements.lastUpdateTime.textContent = `Last Updated: ${utcTime} / ${localTime}`;
                
                // Update nav bar last update time (if element exists)
                const navUpdateElement = document.getElementById('last-update-nav');
                if (navUpdateElement) {
                    navUpdateElement.textContent = `Last Updated: ${utcTime}`;
                }
            })
            .catch(error => {
                console.error('Error fetching last run time:', error);
                this.elements.lastUpdateTime.textContent = 'Last Updated: Unknown';
                
                // Update nav bar
                const navUpdateElement = document.getElementById('last-update-nav');
                if (navUpdateElement) {
                    navUpdateElement.textContent = 'Last Updated: Unknown';
                }
            });
    }

    /**
     * Set up all event listeners
     */
    setupEventListeners() {
        // Search button
        this.elements.searchBtn.addEventListener('click', () => this.handleSearch());

        // Enter key in search box
        this.elements.cveInput.addEventListener('keydown', (event) => {
            if (event.key === 'Enter') {
                this.handleSearch();
            }
        });

        // Export button
        this.elements.exportBtn.addEventListener('click', () => this.handleExport());

        // Filter change (debounced for better performance with rapid changes)
        const debouncedFilterChange = Utils.debounce(() => this.handleFilterChange(), 100);
        this.elements.severityFilter.addEventListener('change', () => debouncedFilterChange());

        // Sort change (debounced for better performance with rapid changes)
        const debouncedSortChange = Utils.debounce(() => this.handleSortChange(), 100);
        this.elements.sortBy.addEventListener('change', () => debouncedSortChange());

        // Modal close events
        this.elements.closeModal.addEventListener('click', () => this.closeModal());
        this.elements.closeModalBtn.addEventListener('click', () => this.closeModal());
        
        // Close modal when clicking outside
        this.elements.modal.addEventListener('click', (event) => {
            if (event.target === this.elements.modal) {
                this.closeModal();
            }
        });
        
        // Close modal on escape key
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && !this.elements.modal.classList.contains('hidden')) {
                this.closeModal();
            }
        });

        // Scoring info panel
        const scoringInfoPanel = document.getElementById('scoring-info-panel');
        const showScoringInfoBtn = document.getElementById('show-scoring-info');
        const closeInfoPanelBtn = document.getElementById('close-info-panel');

        if (showScoringInfoBtn) {
            showScoringInfoBtn.addEventListener('click', () => {
                scoringInfoPanel.classList.remove('hidden');
                this.analytics.trackInfoPanelView();
                scoringInfoPanel.scrollIntoView({ behavior: 'smooth' });
            });
        }

        if (closeInfoPanelBtn) {
            closeInfoPanelBtn.addEventListener('click', () => {
                scoringInfoPanel.classList.add('hidden');
            });
        }
    }

    /**
     * Handle search action
     */
    async handleSearch() {
        // Reset previous results and errors
        this.uiRenderer.hideError();
        this.uiRenderer.hideResults();
        
        // Get and validate input
        const inputText = this.elements.cveInput.value.trim();
        
        if (!inputText) {
            this.uiRenderer.showError('Please enter valid CVE(s)');
            return;
        }
        
        // Parse input into CVE IDs
        const inputCVEs = this.searchEngine.parseInput(inputText);

        if (inputCVEs.length === 0) {
            this.uiRenderer.showError('Please enter valid CVE(s)');
            return;
        }

        // Lazy load data if not already loaded
        const dataLoaded = await this.ensureDataLoaded();
        if (!dataLoaded) {
            return; // Error already shown by ensureDataLoaded
        }

        // Search for CVEs
        const matchedCVEs = this.searchEngine.search(inputCVEs);

        if (matchedCVEs.length === 0) {
            this.uiRenderer.showError('No matching CVEs found');
            return;
        }

        // Store original results and apply filters/sort
        this.originalSearchResults = matchedCVEs;
        const filteredAndSorted = this.applyFiltersAndSort();
        
        // Track search
        this.analytics.trackSearch(inputText, matchedCVEs.length);
        
        // Save to recent searches
        this.saveRecentSearch(inputText);
        
        // Display results
        this.currentResults = filteredAndSorted;
        this.uiRenderer.renderResults(filteredAndSorted);

        // Mark first search done
        if (!this.firstSearchDone) {
            this.firstSearchDone = true;
        }
    }

    /**
     * Handle export action
     */
    handleExport() {
        if (this.currentResults.length === 0) {
            alert('No results to export');
            return;
        }

        try {
            this.exportManager.exportToCSV(this.currentResults);
            this.analytics.trackExport(this.currentResults.length);
        } catch (error) {
            console.error('Export error:', error);
            alert('Error exporting results: ' + error.message);
        }
    }

    /**
     * Handle filter change (debounced for performance)
     */
    handleFilterChange() {
        this.analytics.trackFilterChange('severity', this.elements.severityFilter.value);
        
        if (this.originalSearchResults.length > 0) {
            // Debounce is applied in setupEventListeners
            const filtered = this.applyFiltersAndSort();
            this.currentResults = filtered;
            this.uiRenderer.renderResults(filtered);
        }
    }

    /**
     * Handle sort change (debounced for performance)
     */
    handleSortChange() {
        this.analytics.trackSortChange(this.elements.sortBy.value);
        
        if (this.originalSearchResults.length > 0) {
            // Debounce is applied in setupEventListeners
            const filtered = this.applyFiltersAndSort();
            this.currentResults = filtered;
            this.uiRenderer.renderResults(filtered);
        }
    }

    /**
     * Apply current filters and sorting to original search results
     * @returns {Array<Object>} Filtered and sorted results
     */
    applyFiltersAndSort() {
        const severityFilter = this.elements.severityFilter.value;
        const sortBy = this.elements.sortBy.value;
        return this.searchEngine.filterAndSort(this.originalSearchResults, severityFilter, sortBy);
    }

    /**
     * Show CVE details modal
     * @param {Object} cve - CVE data
     */
    showCVEDetails(cve) {
        this.uiRenderer.showModal(cve);
        this.analytics.trackCVEView(cve.cve, cve['cvss-te_severity']);
    }

    /**
     * Close modal
     */
    closeModal() {
        this.uiRenderer.closeModal();
    }

    /**
     * Save search to recent searches
     * @param {string} searchTerm - Search term
     */
    saveRecentSearch(searchTerm) {
        const recentSearches = JSON.parse(localStorage.getItem('recentSearches') || '[]');
        recentSearches.unshift(searchTerm);
        if (recentSearches.length > CONFIG.MAX_RECENT_SEARCHES) {
            recentSearches.pop();
        }
        localStorage.setItem('recentSearches', JSON.stringify(recentSearches));
        this.displayRecentSearches();
    }

    /**
     * Display recent searches
     */
    displayRecentSearches() {
        const recentSearches = JSON.parse(localStorage.getItem('recentSearches') || '[]');
        this.uiRenderer.displayRecentSearches(recentSearches, (searchTerm) => {
            this.elements.cveInput.value = searchTerm;
            this.handleSearch();
        });
    }

    /**
     * Check URL for pre-filled CVE search
     */
    checkUrlParameters() {
        const urlParams = new URLSearchParams(window.location.search);
        const cveParam = urlParams.get('cve');
        
        if (cveParam) {
            this.elements.cveInput.value = cveParam;
            // Auto-trigger search
            this.handleSearch();
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.cvssApp = new CVSSApp();
});
