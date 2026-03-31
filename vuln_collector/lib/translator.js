const logger = require('./logger');
const db = require('./db');

const SOURCE = 'translator';

// Google Translate 비공식 API (무료, 키 불필요)
const TRANSLATE_URL = 'https://translate.googleapis.com/translate_a/single';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Google Translate로 영어 → 한국어 번역
 */
async function translateText(text) {
  if (!text || text.trim().length === 0) return '';

  // 5000자 제한 (Google Translate 한도)
  const truncated = text.substring(0, 5000);

  const params = new URLSearchParams({
    client: 'gtx',
    sl: 'en',
    tl: 'ko',
    dt: 't',
    q: truncated
  });

  const response = await fetch(`${TRANSLATE_URL}?${params}`, { signal: AbortSignal.timeout(15000) });
  if (!response.ok) {
    throw new Error(`번역 실패: HTTP ${response.status}`);
  }

  const data = await response.json();

  // 응답 형식: [[["번역문","원문",null,null,N],...],null,"en"]
  if (!Array.isArray(data) || !Array.isArray(data[0])) {
    throw new Error('번역 응답 파싱 실패');
  }

  const translated = data[0]
    .filter(segment => segment && segment[0])
    .map(segment => segment[0])
    .join('');

  return translated;
}

/**
 * 미번역 취약점들을 배치로 번역
 * @param {number} batchSize - 한 번에 처리할 건수
 */
async function translateBatch(batchSize = 50) {
  // 미번역 + 제목/설명이 있는 항목 조회
  const rows = await db.query(
    `SELECT id, cve_id, title, description
     FROM vulnerabilities
     WHERE title_ko IS NULL AND title IS NOT NULL AND title != ''
     ORDER BY published_date DESC
     LIMIT ?`,
    [batchSize]
  );

  if (rows.length === 0) {
    logger.info(SOURCE, '번역할 항목 없음');
    return 0;
  }

  logger.info(SOURCE, `${rows.length}건 번역 시작`);
  let translated = 0;

  for (const row of rows) {
    try {
      // 제목 번역
      const titleKo = await translateText(row.title);
      await sleep(300);

      // 설명 번역 (2000자까지)
      let descKo = null;
      if (row.description && row.description.length > 0) {
        const descToTranslate = row.description.substring(0, 2000);
        descKo = await translateText(descToTranslate);
        await sleep(300);
      }

      // 빈 번역 방지 - 원문 유지
      const finalTitle = titleKo && titleKo.trim().length > 0 ? titleKo : null;
      const finalDesc = descKo && descKo.trim().length > 0 ? descKo : null;

      // 제목이라도 번역되었으면 저장
      if (finalTitle) {
        await db.query(
          'UPDATE vulnerabilities SET title_ko = ?, description_ko = ? WHERE id = ?',
          [finalTitle, finalDesc, row.id]
        );
      } else {
        // 번역 실패 시 빈 문자열로 마킹 (재시도 방지)
        await db.query(
          "UPDATE vulnerabilities SET title_ko = '' WHERE id = ? AND title_ko IS NULL",
          [row.id]
        );
      }

      translated++;

      if (translated % 10 === 0) {
        logger.info(SOURCE, `${translated}/${rows.length}건 번역 완료`);
      }
    } catch (err) {
      logger.error(SOURCE, `${row.cve_id} 번역 실패: ${err.message}`);
      // 429 에러 시 대기
      if (err.message.includes('429')) {
        logger.warn(SOURCE, '레이트 리밋 - 60초 대기');
        await sleep(60000);
      }
    }
  }

  logger.info(SOURCE, `번역 완료: ${translated}건`);
  return translated;
}

module.exports = { translateText, translateBatch };
