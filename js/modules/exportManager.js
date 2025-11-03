/**
 * ExportManager Module
 * Handles CSV export functionality
 */

export class ExportManager {
    /**
     * Export results to CSV file
     * @param {Array<Object>} results - CVE results to export
     * @param {string} filename - Output filename (default: 'cvss-te-results.csv')
     */
    exportToCSV(results, filename = 'cvss-te-results.csv') {
        if (!results || results.length === 0) {
            throw new Error('No results to export');
        }

        const csvContent = this.createCSVContent(results);
        this.downloadFile(csvContent, filename);
    }

    /**
     * Create CSV content from results
     * @param {Array<Object>} results - CVE results
     * @returns {string} CSV content
     */
    createCSVContent(results) {
        const headers = [
            'CVE',
            'Base Score',
            'Base Severity',
            'CVSS-BT Score',
            'CVSS-BT Severity',
            'CVSS-TE Score',
            'CVSS-TE Severity',
            'EPSS Score',
            'CVSS-BT Vector',
            'Published Date'
        ];

        const rows = results.map(cve => [
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
        ].join(','));

        return [headers.join(','), ...rows].join('\n');
    }

    /**
     * Trigger file download
     * @param {string} content - File content
     * @param {string} filename - Filename
     */
    downloadFile(content, filename) {
        const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        
        // Clean up the URL object
        URL.revokeObjectURL(url);
    }
}

