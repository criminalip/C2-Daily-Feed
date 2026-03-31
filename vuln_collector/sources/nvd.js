const config = require('../config');
const store = require('../lib/store');
const logger = require('../lib/logger');

const SOURCE = 'nvd';
const BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

// 레이트 리밋: API 키 없이 5req/30s, 있으면 50req/30s
const RATE_LIMIT_DELAY = config.nvdApiKey ? 600 : 6000;

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function formatDate(date) {
  return date.toISOString().replace('Z', '+00:00');
}

function parseSeverity(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

function extractCvssInfo(metrics) {
  // CVSS v3.1 우선, 없으면 v3.0
  if (metrics?.cvssMetricV31?.length > 0) {
    const m = metrics.cvssMetricV31[0].cvssData;
    return { score: m.baseScore, vector: m.vectorString };
  }
  if (metrics?.cvssMetricV30?.length > 0) {
    const m = metrics.cvssMetricV30[0].cvssData;
    return { score: m.baseScore, vector: m.vectorString };
  }
  return { score: null, vector: null };
}

function extractCwes(weaknesses) {
  if (!weaknesses) return [];
  const cwes = [];
  for (const w of weaknesses) {
    for (const d of (w.description || [])) {
      if (d.value && d.value.startsWith('CWE-')) {
        cwes.push(d.value);
      }
    }
  }
  return [...new Set(cwes)];
}

function extractProducts(configurations) {
  if (!configurations) return [];
  const products = [];
  const seen = new Set();

  function walkNodes(nodes) {
    for (const node of nodes) {
      for (const match of (node.cpeMatch || [])) {
        if (!match.criteria) continue;
        // cpe:2.3:a:vendor:product:version:...
        const parts = match.criteria.split(':');
        if (parts.length >= 5) {
          const vendor = parts[3];
          const product = parts[4];
          const key = `${vendor}:${product}`;
          if (!seen.has(key)) {
            seen.add(key);
            let versions = '';
            if (match.versionStartIncluding) versions += `>=${match.versionStartIncluding} `;
            if (match.versionStartExcluding) versions += `>${match.versionStartExcluding} `;
            if (match.versionEndIncluding) versions += `<=${match.versionEndIncluding}`;
            if (match.versionEndExcluding) versions += `<${match.versionEndExcluding}`;
            if (!versions) versions = parts[5] !== '*' ? parts[5] : 'all';
            products.push({ vendor, product, versions: versions.trim() });
          }
        }
      }
      if (node.children) walkNodes(node.children);
    }
  }

  for (const cfg of configurations) {
    if (cfg.nodes) walkNodes(cfg.nodes);
  }
  return products;
}

function extractReferences(refs) {
  if (!refs) return [];
  return refs.map(r => ({ url: r.url, source: r.source || 'NVD' }));
}

async function collect() {
  logger.info(SOURCE, '수집 시작');

  const state = await store.getState(SOURCE);
  let startDate;

  if (state && state.last_successful_fetch) {
    startDate = new Date(state.last_successful_fetch);
  } else {
    startDate = new Date();
    startDate.setDate(startDate.getDate() - config.initialFetchDays);
  }

  const endDate = new Date();
  let startIndex = 0;
  let totalResults = 0;
  let fetchedCount = 0;

  do {
    const params = new URLSearchParams({
      lastModStartDate: formatDate(startDate),
      lastModEndDate: formatDate(endDate),
      startIndex: startIndex.toString(),
      resultsPerPage: '100'
    });

    const url = `${BASE_URL}?${params}`;
    logger.info(SOURCE, `요청: startIndex=${startIndex}`);

    const headers = {};
    if (config.nvdApiKey) headers['apiKey'] = config.nvdApiKey;

    const response = await fetch(url, {
      headers,
      signal: AbortSignal.timeout(30000)
    });

    if (response.status === 429 || response.status >= 500) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();
    totalResults = data.totalResults || 0;

    if (!data.vulnerabilities || data.vulnerabilities.length === 0) break;

    for (const item of data.vulnerabilities) {
      const cve = item.cve;
      if (!cve || !cve.id) continue;

      const cvss = extractCvssInfo(cve.metrics);
      const description = (cve.descriptions || []).find(d => d.lang === 'en')?.value || '';

      const vulnData = {
        cve_id: cve.id,
        title: description.substring(0, 500),
        description: description,
        severity: cvss.score != null ? parseSeverity(cvss.score) : 'NONE',
        cvss_v3_score: cvss.score ?? null,
        cvss_v3_vector: cvss.vector,
        published_date: cve.published ? new Date(cve.published).toISOString().slice(0, 19).replace('T', ' ') : null,
        modified_date: cve.lastModified ? new Date(cve.lastModified).toISOString().slice(0, 19).replace('T', ' ') : null,
        cwes: extractCwes(cve.weaknesses),
        products: extractProducts(cve.configurations),
        references: extractReferences(cve.references),
        sources: [{ source: 'NVD', source_url: `https://nvd.nist.gov/vuln/detail/${cve.id}` }]
      };

      try {
        await store.saveVulnerability(vulnData);
        fetchedCount++;
      } catch (err) {
        logger.error(SOURCE, `${cve.id} 저장 실패: ${err.message}`);
      }
    }

    startIndex += data.vulnerabilities.length;

    // 레이트 리밋 대기
    if (startIndex < totalResults) {
      await sleep(RATE_LIMIT_DELAY);
    }
  } while (startIndex < totalResults);

  // 상태 저장
  await store.setState(SOURCE, {
    last_successful_fetch: endDate.toISOString().slice(0, 19).replace('T', ' ')
  });

  logger.info(SOURCE, `수집 완료: ${fetchedCount}건 처리 (전체 ${totalResults}건)`);
  return fetchedCount;
}

module.exports = { collect };
