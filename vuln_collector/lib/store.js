const db = require('./db');
const logger = require('./logger');
const { notifyIfNeeded } = require('./notifier');

/**
 * 하나의 CVE를 트랜잭션으로 저장
 * MariaDB의 VALUES() 함수는 지원되므로 그대로 사용 (MySQL 8.0.20+ 에서만 deprecated)
 */
async function saveVulnerability(data) {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const cvssScore = data.cvss_v3_score != null ? data.cvss_v3_score : null;

    const [result] = await conn.execute(
      `INSERT INTO vulnerabilities
        (cve_id, title, description, severity, cvss_v3_score, cvss_v3_vector,
         published_date, modified_date, first_seen, last_updated,
         is_kev, kev_due_date, exploit_available, patch_available)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        title = COALESCE(VALUES(title), title),
        description = COALESCE(VALUES(description), description),
        severity = IF(COALESCE(VALUES(cvss_v3_score), 0) >= COALESCE(cvss_v3_score, 0), VALUES(severity), severity),
        cvss_v3_score = GREATEST(COALESCE(cvss_v3_score, 0), COALESCE(VALUES(cvss_v3_score), 0)),
        cvss_v3_vector = IF(COALESCE(VALUES(cvss_v3_score), 0) >= COALESCE(cvss_v3_score, 0), VALUES(cvss_v3_vector), cvss_v3_vector),
        published_date = COALESCE(VALUES(published_date), published_date),
        modified_date = COALESCE(VALUES(modified_date), modified_date),
        last_updated = VALUES(last_updated),
        is_kev = (is_kev OR VALUES(is_kev)),
        kev_due_date = COALESCE(VALUES(kev_due_date), kev_due_date),
        exploit_available = (exploit_available OR VALUES(exploit_available)),
        patch_available = (patch_available OR VALUES(patch_available))`,
      [
        data.cve_id, data.title || null, data.description || null,
        data.severity || 'NONE', cvssScore, data.cvss_v3_vector || null,
        data.published_date || null, data.modified_date || null, now, now,
        data.is_kev ? 1 : 0, data.kev_due_date || null,
        data.exploit_available ? 1 : 0, data.patch_available ? 1 : 0
      ]
    );

    let vulnId = result.insertId;
    if (!vulnId) {
      const [rows] = await conn.execute('SELECT id FROM vulnerabilities WHERE cve_id = ?', [data.cve_id]);
      if (!rows || rows.length === 0) throw new Error(`CVE ${data.cve_id} ID 조회 실패`);
      vulnId = rows[0].id;
    }

    // 영향받는 제품
    if (data.products && data.products.length > 0) {
      for (const p of data.products) {
        await conn.execute(
          'INSERT IGNORE INTO affected_products (vulnerability_id, vendor, product, versions) VALUES (?, ?, ?, ?)',
          [vulnId, p.vendor || null, p.product || null, (p.versions || '').substring(0, 500) || null]
        );
      }
    }

    // 참조 링크
    if (data.references && data.references.length > 0) {
      for (const r of data.references) {
        const url = typeof r === 'string' ? r : r.url;
        const source = typeof r === 'string' ? null : (r.source || null);
        if (!url) continue;
        const truncUrl = url.substring(0, 1000);
        const [existing] = await conn.execute(
          'SELECT id FROM reference_links WHERE vulnerability_id = ? AND url = ?',
          [vulnId, truncUrl]
        );
        if (existing.length === 0) {
          await conn.execute(
            'INSERT INTO reference_links (vulnerability_id, url, source) VALUES (?, ?, ?)',
            [vulnId, truncUrl, source ? source.substring(0, 200) : null]
          );
        }
      }
    }

    // 수집 소스
    if (data.sources && data.sources.length > 0) {
      for (const s of data.sources) {
        await conn.execute(
          `INSERT INTO vulnerability_sources (vulnerability_id, source, source_url)
           VALUES (?, ?, ?)
           ON DUPLICATE KEY UPDATE collected_at = CURRENT_TIMESTAMP, source_url = VALUES(source_url)`,
          [vulnId, (s.source || '').substring(0, 20), s.source_url || null]
        );
      }
    }

    // CWE
    if (data.cwes && data.cwes.length > 0) {
      for (const cweId of data.cwes) {
        await conn.execute('INSERT IGNORE INTO cwe_entries (cwe_id) VALUES (?)', [cweId]);
        const [rows] = await conn.execute('SELECT id FROM cwe_entries WHERE cwe_id = ?', [cweId]);
        if (rows.length > 0) {
          await conn.execute(
            'INSERT IGNORE INTO vulnerability_cwes (vulnerability_id, cwe_id) VALUES (?, ?)',
            [vulnId, rows[0].id]
          );
        }
      }
    }

    await conn.commit();

    // Slack 알림 체크 (트랜잭션 커밋 후, 비동기로 처리하여 수집에 영향 없도록)
    notifyIfNeeded(data).catch(err => {
      logger.error('ALERT', `알림 처리 실패 (${data.cve_id}): ${err.message}`);
    });

    return vulnId;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/**
 * 수집 상태 조회
 */
async function getState(source) {
  const rows = await db.query('SELECT * FROM collector_state WHERE source = ?', [source]);
  return rows.length > 0 ? rows[0] : null;
}

/**
 * 수집 상태 저장
 */
async function setState(source, state) {
  await db.query(
    `INSERT INTO collector_state (source, last_successful_fetch, last_cursor, extra_state)
     VALUES (?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       last_successful_fetch = VALUES(last_successful_fetch),
       last_cursor = VALUES(last_cursor),
       extra_state = VALUES(extra_state)`,
    [
      source,
      state.last_successful_fetch || null,
      state.last_cursor || null,
      state.extra_state ? JSON.stringify(state.extra_state) : null
    ]
  );
}

module.exports = { saveVulnerability, getState, setState };
