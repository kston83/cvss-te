/**
 * CVSS-TE Dashboard Application
 * Main entry point for dashboard page
 */

import { DataManager } from './modules/dataManager.js';
import { DashboardDataManager } from './modules/dashboardDataManager.js';
import { DashboardUIRenderer } from './modules/dashboardUIRenderer.js';
import { Analytics } from './modules/analytics.js';
import { KevEnricher } from './modules/kevEnricher.js';

class DashboardApp {
    constructor() {
        // Initialize modules
        this.dataManager = new DataManager(CONFIG.CSV_PATH);
        this.dashboardData = new DashboardDataManager(this.dataManager);
        this.ui = new DashboardUIRenderer();
        this.analytics = new Analytics();
        this.kevEnricher = new KevEnricher();

        // Store current data for sorting
        this.currentData = {
            kevs: [],
            recent: [],
            emerging: []
        };

        // Initialize
        this.init();
    }

    async init() {
        // Initialize UI renderer
        this.ui.init();

        // Load KEV data and CSV data in parallel
        await Promise.all([
            this.kevEnricher.loadKevData(),
            this.loadData()
        ]);

        // Set up event listeners
        this.setupEventListeners();

        // Render dashboard
        this.renderDashboard();

        // Fetch last update time
        this.fetchLastUpdateTime();
    }

    /**
     * Load CSV data
     */
    async loadData() {
        try {
            await this.dataManager.loadData();
            
            // Enrich CVE data with KEV dates after loading
            if (this.kevEnricher.kevMap.size > 0) {
                const enrichedData = this.kevEnricher.enrichCves(this.dataManager.getData());
                // Update the data manager with enriched data
                this.dataManager.data = enrichedData;
            }
        } catch (error) {
            console.error('Error loading data:', error);
            alert('Error loading CVE data. Please refresh the page.');
        }
    }

    /**
     * Render all dashboard sections
     */
    renderDashboard() {
        // Get data
        const stats = this.dashboardData.getStatistics();
        // KEVs default to most recent (by last_modified_date)
        this.currentData.kevs = this.dashboardData.getCisaKevs(10, 'date_desc');
        this.currentData.recent = this.dashboardData.getRecentCves(7, 20);
        this.currentData.emerging = this.dashboardData.getEmergingThreats(90, 15);

        // Render
        this.ui.renderStatistics(stats);
        this.ui.renderKevs(this.currentData.kevs);
        this.ui.renderRecent(this.currentData.recent);
        this.ui.renderEmerging(this.currentData.emerging);

        // Show content
        this.ui.showContent();

        // Track page view
        this.analytics.track('dashboard_view', {
            kev_count: this.currentData.kevs.length,
            recent_count: this.currentData.recent.length,
            emerging_count: this.currentData.emerging.length
        });
    }

    /**
     * Set up event listeners
     */
    setupEventListeners() {
        // Quick search
        const quickSearchBtn = document.getElementById('quick-search-btn');
        const quickSearchInput = document.getElementById('quick-search-input');

        quickSearchBtn.addEventListener('click', () => this.handleQuickSearch());
        quickSearchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.handleQuickSearch();
        });

        // Recent days filter
        const recentDaysFilter = document.getElementById('recent-days-filter');
        recentDaysFilter.addEventListener('change', (e) => {
            const days = parseInt(e.target.value);
            this.currentData.recent = this.dashboardData.getRecentCves(days, 20);
            this.ui.renderRecent(this.currentData.recent);
            this.analytics.track('filter_recent', { days });
        });

        // KEV sort - re-fetch with new sort criteria
        const kevSort = document.getElementById('kev-sort');
        kevSort.addEventListener('change', (e) => {
            // Re-fetch KEVs with the new sort order
            this.currentData.kevs = this.dashboardData.getCisaKevs(10, e.target.value);
            this.ui.renderKevs(this.currentData.kevs);
            this.analytics.track('sort_kev', { sort: e.target.value });
        });

        // Recent sort
        const recentSort = document.getElementById('recent-sort');
        recentSort.addEventListener('change', (e) => {
            const sorted = this.dashboardData.sortCves(this.currentData.recent, e.target.value);
            this.ui.renderRecent(sorted);
            this.analytics.track('sort_recent', { sort: e.target.value });
        });

        // Emerging threats days filter
        const emergingDaysFilter = document.getElementById('emerging-days-filter');
        emergingDaysFilter.addEventListener('change', (e) => {
            const days = parseInt(e.target.value);
            this.currentData.emerging = this.dashboardData.getEmergingThreats(days, 15);
            this.ui.renderEmerging(this.currentData.emerging);
            this.analytics.track('filter_emerging', { days });
        });

        // Emerging threats sort
        const emergingSort = document.getElementById('emerging-sort');
        emergingSort.addEventListener('change', (e) => {
            const sorted = this.dashboardData.sortCves(this.currentData.emerging, e.target.value);
            this.ui.renderEmerging(sorted);
            this.analytics.track('sort_emerging', { sort: e.target.value });
        });
    }

    /**
     * Handle quick search
     */
    handleQuickSearch() {
        const input = document.getElementById('quick-search-input');
        const searchTerm = input.value.trim();
        
        if (searchTerm) {
            // Navigate to lookup page with pre-filled search
            window.location.href = `/lookup.html?cve=${encodeURIComponent(searchTerm)}`;
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
                const utcTime = lastRunDate.toLocaleString('en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    timeZone: 'UTC'
                }) + ' UTC';
                
                document.getElementById('last-update-nav').textContent = `Last Updated: ${utcTime}`;
            })
            .catch(error => {
                console.error('Error fetching last run time:', error);
                document.getElementById('last-update-nav').textContent = 'Last Updated: Unknown';
            });
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboardApp = new DashboardApp();
});

