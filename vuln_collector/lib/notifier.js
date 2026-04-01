const config = require('../config');
const db = require('./db');
const logger = require('./logger');

const SLACK_WEBHOOK_URL = config.slack.webhookUrl;

// RCE 관련 CWE
const CWE_RCE = new Set([
  'CWE-78',   // OS Command Injection
  'CWE-94',   // Code Injection
  'CWE-95',   // Eval Injection
  'CWE-502',  // Deserialization of Untrusted Data
  'CWE-917',  // Expression Language Injection
  'CWE-1321', // Prototype Pollution
]);

// 인증우회 관련 CWE
const CWE_AUTH_BYPASS = new Set([
  'CWE-287',  // Improper Authentication
  'CWE-288',  // Authentication Bypass Using Alternate Path
  'CWE-290',  // Authentication Bypass by Spoofing
  'CWE-294',  // Authentication Bypass by Capture-replay
  'CWE-306',  // Missing Authentication for Critical Function
  'CWE-307',  // Improper Restriction of Excessive Auth Attempts
  'CWE-863',  // Incorrect Authorization
  'CWE-1390', // Weak Authentication
]);

// 권한상승 관련 CWE
const CWE_PRIV_ESCALATION = new Set([
  'CWE-250',  // Execution with Unnecessary Privileges
  'CWE-269',  // Improper Privilege Management
  'CWE-270',  // Privilege Context Switching Error
  'CWE-271',  // Privilege Dropping / Lowering Errors
  'CWE-274',  // Improper Handling of Insufficient Privileges
  'CWE-862',  // Missing Authorization
]);

// 키워드 매칭 (CWE 없거나 매핑 안 된 경우 보완)
const KEYWORDS_RCE = [
  /\bremote\s+code\s+execut/i,
  /\brce\b/i,
  /\bcommand\s+inject/i,
  /\bcode\s+inject/i,
  /\b원격\s*코드\s*실행/,
  /\b명령어?\s*삽?입?\s*주입/,
  /\b코드\s*실행/,
];

const KEYWORDS_AUTH_BYPASS = [
  /\bauth(?:entication)?\s+bypass/i,
  /\bbypass\s+auth/i,
  /\b인증\s*우회/,
  /\b인증\s*없이/,
  /\b인증\s*취약/,
];

const KEYWORDS_PRIV_ESCALATION = [
  /\bprivilege\s+escalat/i,
  /\bpriv(?:ilege)?\s*esc/i,
  /\belevat(?:e|ion)\s+(?:of\s+)?privil/i,
  /\b권한\s*상승/,
  /\b권한\s*탈취/,
];

/**
 * CWE 목록과 제목/설명으로 취약점 카테고리 분류
 * @returns {string[]} 해당 카테고리 목록 (예: ['RCE', '권한상승'])
 */
function classifyVulnerability(cwes, title, description) {
  const categories = [];
  const cweSet = new Set(cwes || []);
  const text = `${title || ''} ${description || ''}`;

  // CWE 기반 분류
  const hasCweRce = [...cweSet].some(c => CWE_RCE.has(c));
  const hasCweAuth = [...cweSet].some(c => CWE_AUTH_BYPASS.has(c));
  const hasCwePriv = [...cweSet].some(c => CWE_PRIV_ESCALATION.has(c));

  // 키워드 기반 분류
  const hasKwRce = KEYWORDS_RCE.some(r => r.test(text));
  const hasKwAuth = KEYWORDS_AUTH_BYPASS.some(r => r.test(text));
  const hasKwPriv = KEYWORDS_PRIV_ESCALATION.some(r => r.test(text));

  if (hasCweRce || hasKwRce) categories.push('RCE');
  if (hasCweAuth || hasKwAuth) categories.push('인증우회');
  if (hasCwePriv || hasKwPriv) categories.push('권한상승');

  return categories;
}

/**
 * 이미 알림을 보낸 CVE인지 확인
 */
async function isAlreadyAlerted(cveId) {
  const rows = await db.query('SELECT 1 FROM alert_history WHERE cve_id = ?', [cveId]);
  return rows.length > 0;
}

/**
 * 알림 기록 저장
 */
async function markAlerted(cveId, categories) {
  await db.query(
    'INSERT IGNORE INTO alert_history (cve_id, categories) VALUES (?, ?)',
    [cveId, categories.join(',')]
  );
}

/**
 * Slack 메시지 전송
 */
async function sendSlack(payload) {
  if (!SLACK_WEBHOOK_URL) {
    logger.warn('ALERT', 'SLACK_WEBHOOK_URL이 설정되지 않아 알림 스킵');
    return false;
  }

  try {
    const res = await fetch(SLACK_WEBHOOK_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const body = await res.text();
      logger.error('ALERT', `Slack 전송 실패: ${res.status} ${body}`);
      return false;
    }
    return true;
  } catch (err) {
    logger.error('ALERT', `Slack 전송 오류: ${err.message}`);
    return false;
  }
}

/**
 * 취약점 알림 메시지 구성 및 전송
 */
async function notifyIfNeeded(data) {
  if (!SLACK_WEBHOOK_URL) return;

  const cvss = data.cvss_v3_score;
  if (cvss == null || cvss < 8.0) return;

  // 카테고리 분류
  const title = data.title_ko || data.title || '';
  const description = data.description_ko || data.description || '';
  const categories = classifyVulnerability(data.cwes, title, description);

  if (categories.length === 0) return;

  // 중복 알림 방지
  if (await isAlreadyAlerted(data.cve_id)) return;

  // 심각도별 이모지
  const severityEmoji = cvss >= 9.0 ? ':rotating_light:' : ':warning:';
  const severityLabel = cvss >= 9.0 ? 'CRITICAL' : 'HIGH';
  const categoryLabel = categories.join(' / ');

  // 한글 제목 (첫 문장만, 최대 100자)
  const titleKo = data.title_ko || data.description_ko || '';
  const shortTitle = (titleKo || title).split(/[.。]\s*/)[0].substring(0, 100) || '(제목 없음)';

  // 발행일
  const pubDate = data.published_date
    ? new Date(data.published_date).toISOString().split('T')[0]
    : '(미상)';

  // 제품 정보
  const products = (data.products || [])
    .slice(0, 5)
    .map(p => `${p.vendor || '?'}/${p.product || '?'}`)
    .join(', ');

  // 소스 정보
  const sources = (data.sources || []).map(s => s.source).join(', ');

  const blocks = [
    {
      type: 'header',
      text: {
        type: 'plain_text',
        text: `${severityEmoji} [${severityLabel}] ${data.cve_id} (CVSS ${cvss})`,
        emoji: true,
      },
    },
    {
      type: 'section',
      text: {
        type: 'mrkdwn',
        text: `*${shortTitle}*`,
      },
    },
    {
      type: 'section',
      fields: [
        { type: 'mrkdwn', text: `*분류:* ${categoryLabel}` },
        { type: 'mrkdwn', text: `*발행일:* ${pubDate}` },
        ...(products ? [{ type: 'mrkdwn', text: `*영향 제품:* ${products}` }] : []),
        ...(sources ? [{ type: 'mrkdwn', text: `*수집 소스:* ${sources}` }] : []),
        { type: 'mrkdwn', text: `*KEV:* ${data.is_kev ? '예' : '아니오'}` },
        { type: 'mrkdwn', text: `*Exploit:* ${data.exploit_available ? '있음' : '없음'}` },
      ],
    },
    {
      type: 'actions',
      elements: [
        {
          type: 'button',
          text: { type: 'plain_text', text: '상세보기' },
          url: `https://192.168.111.28/vulnfeed/detail/${data.cve_id}`,
        },
        {
          type: 'button',
          text: { type: 'plain_text', text: 'MITRE' },
          url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${data.cve_id}`,
        },
      ],
    },
  ];

  const sent = await sendSlack({
    text: `${severityEmoji} [${severityLabel}] ${data.cve_id} - ${shortTitle} (CVSS ${cvss})`,
    blocks,
  });

  if (sent) {
    await markAlerted(data.cve_id, categories);
    logger.info('ALERT', `Slack 알림 전송: ${data.cve_id} [${categoryLabel}] CVSS=${cvss}`);
  }
}

module.exports = { notifyIfNeeded, classifyVulnerability };
