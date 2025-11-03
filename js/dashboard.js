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
        // Initialize analytics first
        this.analytics = new Analytics();
        
        // Initialize modules
        this.dataManager = new DataManager(CONFIG.CSV_PATH);
        this.dashboardData = new DashboardDataManager(this.dataManager);
        this.ui = new DashboardUIRenderer(this.analytics);
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
        const startTime = Date.now();
        
        // Initialize UI renderer
        this.ui.init();

        // Track page view
        this.analytics.trackPageView('dashboard', {
            'referrer': document.referrer || 'direct'
        });

        // Load KEV data and CSV data in parallel
        const kevStartTime = Date.now();
        const csvStartTime = Date.now();
        
        try {
            await Promise.all([
                this.kevEnricher.loadKevData().then(() => {
                    const kevLoadTime = Date.now() - kevStartTime;
                    this.analytics.trackDataLoad('kev', kevLoadTime, true);
                }),
                this.loadData().then(() => {
                    const csvLoadTime = Date.now() - csvStartTime;
                    this.analytics.trackDataLoad('csv', csvLoadTime, true);
                })
            ]);
        } catch (error) {
            this.analytics.trackDataLoad('combined', Date.now() - startTime, false);
            throw error;
        }

        // Set up event listeners
        this.setupEventListeners();

        // Render dashboard
        this.renderDashboard();

        // Fetch last update time
        this.fetchLastUpdateTime();
        
        // Track banner view (if not dismissed)
        const bannerDismissed = localStorage.getItem('cvss_te_banner_dismissed');
        if (bannerDismissed !== 'true') {
            this.analytics.trackBanner('about_cvss_te', 'view');
        }
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

        // Track dashboard statistics and sections loaded
        this.analytics.trackDashboardStats(stats);
        this.analytics.trackDashboardSection('cisa_kevs', 'view', {
            'count': this.currentData.kevs.length
        });
        this.analytics.trackDashboardSection('recent_cves', 'view', {
            'count': this.currentData.recent.length,
            'days_filter': 7
        });
        this.analytics.trackDashboardSection('emerging_threats', 'view', {
            'count': this.currentData.emerging.length,
            'days_filter': 90
        });
    }

    /**
     * Set up event listeners
     */
    setupEventListeners() {
        // About banner management
        this.setupAboutBanner();
        
        // Learn more modal
        this.setupLearnMoreModal();
        
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
            this.analytics.trackDashboardControl('recent_cves', 'filter', days.toString());
            this.analytics.trackDashboardSection('recent_cves', 'filter', {
                days: days,
                count: this.currentData.recent.length
            });
        });

        // KEV sort - re-fetch with new sort criteria
        const kevSort = document.getElementById('kev-sort');
        kevSort.addEventListener('change', (e) => {
            // Re-fetch KEVs with the new sort order
            const sortValue = e.target.value;
            this.currentData.kevs = this.dashboardData.getCisaKevs(10, sortValue);
            this.ui.renderKevs(this.currentData.kevs);
            this.analytics.trackDashboardControl('cisa_kevs', 'sort', sortValue);
            this.analytics.trackDashboardSection('cisa_kevs', 'sort', {
                sort_by: sortValue,
                count: this.currentData.kevs.length
            });
        });

        // Recent sort
        const recentSort = document.getElementById('recent-sort');
        recentSort.addEventListener('change', (e) => {
            const sorted = this.dashboardData.sortCves(this.currentData.recent, e.target.value);
            this.ui.renderRecent(sorted);
            this.analytics.trackDashboardControl('recent_cves', 'sort', e.target.value);
            this.analytics.trackDashboardSection('recent_cves', 'sort', {
                sort_by: e.target.value
            });
        });

        // Emerging threats days filter
        const emergingDaysFilter = document.getElementById('emerging-days-filter');
        emergingDaysFilter.addEventListener('change', (e) => {
            const days = parseInt(e.target.value);
            this.currentData.emerging = this.dashboardData.getEmergingThreats(days, 15);
            this.ui.renderEmerging(this.currentData.emerging);
            this.analytics.trackDashboardControl('emerging_threats', 'filter', days.toString());
            this.analytics.trackDashboardSection('emerging_threats', 'filter', {
                days: days,
                count: this.currentData.emerging.length
            });
        });

        // Emerging threats sort
        const emergingSort = document.getElementById('emerging-sort');
        emergingSort.addEventListener('change', (e) => {
            const sorted = this.dashboardData.sortCves(this.currentData.emerging, e.target.value);
            this.ui.renderEmerging(sorted);
            this.analytics.trackDashboardControl('emerging_threats', 'sort', e.target.value);
            this.analytics.trackDashboardSection('emerging_threats', 'sort', {
                sort_by: e.target.value
            });
        });
    }

    /**
     * Setup about CVSS-TE banner
     */
    setupAboutBanner() {
        const banner = document.getElementById('about-cvss-te');
        const closeBtn = document.getElementById('about-close-btn');
        
        // Check if user has dismissed banner before
        const dismissed = localStorage.getItem('cvss_te_banner_dismissed');
        if (dismissed === 'true') {
            banner.style.display = 'none';
        }
        
        // Handle close button
        closeBtn.addEventListener('click', () => {
            banner.style.display = 'none';
            localStorage.setItem('cvss_te_banner_dismissed', 'true');
            this.analytics.trackBanner('about_cvss_te', 'dismiss');
        });
        
        // Track external link clicks in banner
        const bannerLinks = banner.querySelectorAll('a[target="_blank"]');
        bannerLinks.forEach(link => {
            link.addEventListener('click', () => {
                this.analytics.trackExternalLink(link.href, 'about_banner');
                this.analytics.trackBanner('about_cvss_te', 'click_external_link');
            });
        });
    }

    /**
     * Setup learn more modal
     */
    setupLearnMoreModal() {
        const modal = document.getElementById('learn-more-modal');
        const openBtn = document.getElementById('learn-more-btn');
        const closeBtn = document.getElementById('modal-close-btn');
        
        // Open modal
        openBtn.addEventListener('click', () => {
            modal.classList.remove('hidden');
            this.analytics.trackModal('learn_more', 'open', { source: 'banner_button' });
            this.analytics.trackBanner('about_cvss_te', 'click_learn_more');
        });
        
        // Close modal
        const closeModal = (trigger) => {
            modal.classList.add('hidden');
            this.analytics.trackModal('learn_more', 'close', { trigger: trigger || 'unknown' });
        };
        
        closeBtn.addEventListener('click', () => closeModal('close_button'));
        
        // Close on background click
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal('background_click');
            }
        });
        
        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && !modal.classList.contains('hidden')) {
                closeModal('escape_key');
            }
        });
        
        // Track external link clicks in modal
        const modalLinks = modal.querySelectorAll('a[target="_blank"]');
        modalLinks.forEach(link => {
            link.addEventListener('click', () => {
                this.analytics.trackExternalLink(link.href, 'learn_more_modal');
                this.analytics.trackModal('learn_more', 'click_external_link', {
                    url: link.href,
                    text: link.textContent.trim()
                });
            });
        });
    }

    /**
     * Handle quick search
     */
    handleQuickSearch() {
        const input = document.getElementById('quick-search-input');
        const searchTerm = input.value.trim();
        
        if (searchTerm) {
            // Track quick search
            this.analytics.trackQuickSearch(searchTerm, 'dashboard_hero');
            this.analytics.trackNavigation('dashboard', 'lookup', 'quick_search');
            
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

