#!/bin/bash
# Download CISA KEV Catalog
# Run: bash data/kev/download_kev.sh

echo "📥 Downloading CISA KEV Catalog..."
curl -L -o data/kev/known_exploited_vulnerabilities.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

if [ $? -eq 0 ]; then
    echo "✅ KEV catalog downloaded successfully!"
    echo "📊 File size:"
    ls -lh data/kev/known_exploited_vulnerabilities.json | awk '{print $5}'
else
    echo "❌ Download failed!"
    exit 1
fi

