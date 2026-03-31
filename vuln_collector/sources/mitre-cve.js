const config = require('../config');
const store = require('../lib/store');
const logger = require('../lib/logger');

const SOURCE = 'mitre';
const DELTA_URL = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function parseSeverity(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

function extractFromCveRecord(cve) {
  const cna = cve.containers?.cna;
  if (!cna) return null;

  // 설명
  const descArr = cna.descriptions || [];
  const enDesc = descArr.find(d => d.lang === 'en')?.value || descArr[0]?.value || '';

  // CVSS
  let cvssScore = null;
  let cvssVector = null;
  const metrics = cna.metrics || [];
  for (const m of metrics) {
    const data = m.cvssV3_1 || m.cvssV3_0;
    if (data) {
      cvssScore = data.baseScore;
      cvssVector = data.vectorString;
      break;
    }
  }

  // CWEs
  const cwes = [];
  for (const pd of (cna.problemTypes || [])) {
    for (const d of (pd.descriptions || [])) {
      if (d.cweId) cwes.push(d.cweId);
      else if (d.description && d.description.startsWith('CWE-')) cwes.push(d.description.split(' ')[0]);
    }
  }

  // 영향받는 제품
  const products = [];
  for (const aff of (cna.affected || [])) {
    const vendor = aff.vendor || 'unknown';
    const product = aff.product || 'unknown';
    const versions = (aff.versions || [])
      .map(v => {
        let s = v.version || '';
        if (v.lessThan) s += ` ~ <${v.lessThan}`;
        if (v.lessThanOrEqual) s += ` ~ <=${v.lessThanOrEqual}`;
        return s;
      })
      .join(', ');
    products.push({ vendor, product, versions: versions || 'unknown' });
  }

  // 참조 링크
  const references = (cna.references || []).map(r => ({
    url: r.url,
    source: 'MITRE'
  }));

  return {
    title: enDesc.substring(0, 500),
    description: enDesc,
    cvss_v3_score: cvssScore ?? null,
    cvss_v3_vector: cvssVector,
    severity: cvssScore != null ? parseSeverity(cvssScore) : 'NONE',
    cwes,
    products,
    references
  };
}

async function fetchCveRecord(githubLink) {
  const response = await fetch(githubLink, { signal: AbortSignal.timeout(15000) });
  if (!response.ok) return null;
  return response.json();
}

async function collect() {
  logger.info(SOURCE, '수집 시작 (deltaLog 방식)');

  // deltaLog.json에서 최근 변경 CVE 목록 가져오기
  const response = await fetch(DELTA_URL, { signal: AbortSignal.timeout(30000) });
  if (!response.ok) {
    throw new Error(`deltaLog 조회 실패: HTTP ${response.status}`);
  }

  const deltaLog = await response.json();
  if (!Array.isArray(deltaLog) || deltaLog.length === 0) {
    logger.info(SOURCE, 'deltaLog에 변경사항 없음');
    return 0;
  }

  // 최근 상태 확인
  const state = await store.getState(SOURCE);
  const lastFetch = state?.last_successful_fetch ? new Date(state.last_successful_fetch) : null;

  let fetchedCount = 0;
  const processedIds = new Set();

  for (const delta of deltaLog) {
    const fetchTime = new Date(delta.fetchTime);

    // 이미 처리한 시점 이전이면 스킵
    if (lastFetch && fetchTime <= lastFetch) continue;

    const allCves = [
      ...(delta.new || []),
      ...(delta.updated || [])
    ];

    for (const entry of allCves) {
      if (!entry.cveId || processedIds.has(entry.cveId)) continue;
      processedIds.add(entry.cveId);

      // 개별 CVE 레코드 조회
      const githubLink = entry.githubLink;
      if (!githubLink) continue;

      try {
        const cveRecord = await fetchCveRecord(githubLink);
        if (!cveRecord) continue;

        // PUBLISHED 상태만 처리
        if (cveRecord.cveMetadata?.state !== 'PUBLISHED') continue;

        const extracted = extractFromCveRecord(cveRecord);
        if (!extracted) continue;

        const published = cveRecord.cveMetadata?.datePublished;
        const modified = cveRecord.cveMetadata?.dateUpdated || entry.dateUpdated;

        const vulnData = {
          cve_id: entry.cveId,
          ...extracted,
          published_date: published ? new Date(published).toISOString().slice(0, 19).replace('T', ' ') : null,
          modified_date: modified ? new Date(modified).toISOString().slice(0, 19).replace('T', ' ') : null,
          sources: [{ source: 'MITRE', source_url: entry.cveOrgLink || `https://www.cve.org/CVERecord?id=${entry.cveId}` }]
        };

        await store.saveVulnerability(vulnData);
        fetchedCount++;

        // 레이트 리밋: GitHub raw 요청 간 간격
        await sleep(200);
      } catch (err) {
        logger.error(SOURCE, `${entry.cveId} 처리 실패: ${err.message}`);
      }
    }
  }

  await store.setState(SOURCE, {
    last_successful_fetch: new Date().toISOString().slice(0, 19).replace('T', ' ')
  });

  logger.info(SOURCE, `수집 완료: ${fetchedCount}건 처리`);
  return fetchedCount;
}

module.exports = { collect };
