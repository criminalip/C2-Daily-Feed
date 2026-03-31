const config = require('../config');
const store = require('../lib/store');
const logger = require('../lib/logger');

const SOURCE = 'github';
const GRAPHQL_URL = 'https://api.github.com/graphql';

function parseSeverity(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'NONE';
}

// GitHub severity → DB ENUM 매핑
const SEVERITY_MAP = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MODERATE: 'MEDIUM',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NONE: 'NONE'
};

const QUERY = `
query($after: String, $updatedSince: DateTime) {
  securityAdvisories(
    first: 100
    after: $after
    updatedSince: $updatedSince
    orderBy: { field: UPDATED_AT, direction: DESC }
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      cvss {
        score
        vectorString
      }
      cwes(first: 10) {
        nodes {
          cweId
          name
        }
      }
      identifiers {
        type
        value
      }
      references {
        url
      }
      vulnerabilities(first: 20) {
        nodes {
          package {
            ecosystem
            name
          }
          vulnerableVersionRange
          firstPatchedVersion {
            identifier
          }
        }
      }
    }
  }
}
`;

async function collect() {
  if (!config.githubToken) {
    logger.warn(SOURCE, 'GITHUB_TOKEN 없음 - 스킵');
    return 0;
  }

  logger.info(SOURCE, '수집 시작');

  const state = await store.getState(SOURCE);
  let updatedSince;

  if (state && state.last_successful_fetch) {
    updatedSince = new Date(state.last_successful_fetch).toISOString();
  } else {
    const d = new Date();
    d.setDate(d.getDate() - config.initialFetchDays);
    updatedSince = d.toISOString();
  }

  let after = null;
  let fetchedCount = 0;
  let hasMore = true;

  while (hasMore) {
    const variables = { updatedSince, after };

    const response = await fetch(GRAPHQL_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${config.githubToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ query: QUERY, variables }),
      signal: AbortSignal.timeout(30000)
    });

    if (response.status === 429 || response.status >= 500) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    if (!response.ok) {
      const body = await response.text();
      throw new Error(`HTTP ${response.status}: ${body.substring(0, 200)}`);
    }

    const result = await response.json();

    if (result.errors) {
      throw new Error(`GraphQL 오류: ${JSON.stringify(result.errors[0].message)}`);
    }

    const advisories = result.data?.securityAdvisories;
    if (!advisories || !advisories.nodes || advisories.nodes.length === 0) {
      break;
    }

    for (const adv of advisories.nodes) {
      // CVE ID 추출
      const cveIdent = (adv.identifiers || []).find(id => id.type === 'CVE');
      if (!cveIdent) continue; // CVE 없는 advisory는 스킵

      const cveId = cveIdent.value;
      const cvssScore = adv.cvss?.score || null;

      // 영향받는 패키지
      const products = (adv.vulnerabilities?.nodes || []).map(v => ({
        vendor: v.package?.ecosystem || 'unknown',
        product: v.package?.name || 'unknown',
        versions: v.vulnerableVersionRange || 'unknown'
      }));

      // CWE
      const cwes = (adv.cwes?.nodes || []).map(c => c.cweId);

      // 참조 링크
      const references = (adv.references || []).map(r => ({
        url: r.url,
        source: 'GitHub'
      }));

      const vulnData = {
        cve_id: cveId,
        title: (adv.summary || '').substring(0, 500),
        description: adv.description || adv.summary || '',
        severity: cvssScore != null ? parseSeverity(cvssScore) : (SEVERITY_MAP[(adv.severity || '').toUpperCase()] || 'NONE'),
        cvss_v3_score: cvssScore ?? null,
        cvss_v3_vector: adv.cvss?.vectorString || null,
        published_date: adv.publishedAt ? new Date(adv.publishedAt).toISOString().slice(0, 19).replace('T', ' ') : null,
        modified_date: adv.updatedAt ? new Date(adv.updatedAt).toISOString().slice(0, 19).replace('T', ' ') : null,
        patch_available: (adv.vulnerabilities?.nodes || []).some(v => v.firstPatchedVersion),
        cwes,
        products,
        references,
        sources: [{ source: 'GitHub', source_url: `https://github.com/advisories/${adv.ghsaId}` }]
      };

      try {
        await store.saveVulnerability(vulnData);
        fetchedCount++;
      } catch (err) {
        logger.error(SOURCE, `${cveId} 저장 실패: ${err.message}`);
      }
    }

    hasMore = advisories.pageInfo.hasNextPage;
    after = advisories.pageInfo.endCursor;

    if (hasMore) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }

  await store.setState(SOURCE, {
    last_successful_fetch: new Date().toISOString().slice(0, 19).replace('T', ' '),
    last_cursor: after
  });

  logger.info(SOURCE, `수집 완료: ${fetchedCount}건 처리`);
  return fetchedCount;
}

module.exports = { collect };
