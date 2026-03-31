const store = require('../lib/store');
const logger = require('../lib/logger');

const SOURCE = 'cisa_kev';
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

async function collect() {
  logger.info(SOURCE, '수집 시작');

  const response = await fetch(KEV_URL, { signal: AbortSignal.timeout(60000) });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const data = await response.json();
  const vulnerabilities = data.vulnerabilities || [];

  if (vulnerabilities.length === 0) {
    logger.warn(SOURCE, '카탈로그에 데이터 없음');
    return 0;
  }

  logger.info(SOURCE, `카탈로그 총 ${vulnerabilities.length}건 로드`);

  // DB에 이미 KEV로 마킹된 CVE 목록 조회
  const state = await store.getState(SOURCE);
  const lastCount = state?.extra_state?.catalogCount || 0;

  let fetchedCount = 0;

  for (const item of vulnerabilities) {
    const cveId = item.cveID;
    if (!cveId) continue;

    const vulnData = {
      cve_id: cveId,
      title: item.vulnerabilityName || null,
      description: item.shortDescription || null,
      severity: null,
      cvss_v3_score: null,
      cvss_v3_vector: null,
      published_date: item.dateAdded ? `${item.dateAdded} 00:00:00` : null,
      modified_date: null,
      is_kev: true,
      kev_due_date: item.dueDate || null,
      exploit_available: true, // KEV에 있으면 기본적으로 exploit 존재
      products: item.vendorProject && item.product ? [{
        vendor: item.vendorProject,
        product: item.product,
        versions: 'all'
      }] : [],
      references: item.notes ? [{ url: item.notes, source: 'CISA KEV' }] : [],
      sources: [{ source: 'CISA_KEV', source_url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }],
      cwes: []
    };

    try {
      await store.saveVulnerability(vulnData);
      fetchedCount++;
    } catch (err) {
      logger.error(SOURCE, `${cveId} 저장 실패: ${err.message}`);
    }
  }

  await store.setState(SOURCE, {
    last_successful_fetch: new Date().toISOString().slice(0, 19).replace('T', ' '),
    extra_state: { catalogCount: vulnerabilities.length }
  });

  logger.info(SOURCE, `수집 완료: ${fetchedCount}건 처리`);
  return fetchedCount;
}

module.exports = { collect };
