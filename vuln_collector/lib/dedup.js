/**
 * CVE 중복 제거 및 병합 로직
 * DB의 ON DUPLICATE KEY UPDATE와 연계하여 동작
 */

/**
 * 여러 소스에서 수집된 동일 CVE 데이터를 병합
 * @param {Object} existing - 기존 데이터
 * @param {Object} incoming - 새로 수집된 데이터
 * @returns {Object} 병합된 데이터
 */
function mergeVulnerability(existing, incoming) {
  const merged = { ...existing };

  // 높은 CVSS 유지
  if (incoming.cvss_v3_score && (!existing.cvss_v3_score || incoming.cvss_v3_score > existing.cvss_v3_score)) {
    merged.cvss_v3_score = incoming.cvss_v3_score;
    merged.cvss_v3_vector = incoming.cvss_v3_vector;
    merged.severity = incoming.severity;
  }

  // 제목/설명은 더 긴 것 유지
  if (incoming.title && (!existing.title || incoming.title.length > existing.title.length)) {
    merged.title = incoming.title;
  }
  if (incoming.description && (!existing.description || incoming.description.length > existing.description.length)) {
    merged.description = incoming.description;
  }

  // 날짜는 더 이른 것 유지
  if (incoming.published_date && (!existing.published_date || incoming.published_date < existing.published_date)) {
    merged.published_date = incoming.published_date;
  }

  // KEV, exploit, patch는 OR
  merged.is_kev = existing.is_kev || incoming.is_kev;
  merged.exploit_available = existing.exploit_available || incoming.exploit_available;
  merged.patch_available = existing.patch_available || incoming.patch_available;

  // kev_due_date
  if (incoming.kev_due_date) merged.kev_due_date = incoming.kev_due_date;

  // references 합치기 (URL 기준 중복 제거)
  const existingRefs = new Set((existing.references || []).map(r => typeof r === 'string' ? r : r.url));
  merged.references = [...(existing.references || [])];
  for (const r of (incoming.references || [])) {
    const url = typeof r === 'string' ? r : r.url;
    if (!existingRefs.has(url)) {
      merged.references.push(r);
      existingRefs.add(url);
    }
  }

  // sources 합치기
  const existingSources = new Set((existing.sources || []).map(s => s.source));
  merged.sources = [...(existing.sources || [])];
  for (const s of (incoming.sources || [])) {
    if (!existingSources.has(s.source)) {
      merged.sources.push(s);
      existingSources.add(s.source);
    }
  }

  // CWE 합치기
  merged.cwes = [...new Set([...(existing.cwes || []), ...(incoming.cwes || [])])];

  // products 합치기
  const existingProducts = new Set((existing.products || []).map(p => `${p.vendor}:${p.product}`));
  merged.products = [...(existing.products || [])];
  for (const p of (incoming.products || [])) {
    const key = `${p.vendor}:${p.product}`;
    if (!existingProducts.has(key)) {
      merged.products.push(p);
      existingProducts.add(key);
    }
  }

  return merged;
}

/**
 * 배열에서 CVE ID 기준 중복 제거 및 병합
 */
function deduplicateArray(items) {
  const map = new Map();
  for (const item of items) {
    if (!item.cve_id) continue;
    if (map.has(item.cve_id)) {
      map.set(item.cve_id, mergeVulnerability(map.get(item.cve_id), item));
    } else {
      map.set(item.cve_id, item);
    }
  }
  return [...map.values()];
}

module.exports = { mergeVulnerability, deduplicateArray };
