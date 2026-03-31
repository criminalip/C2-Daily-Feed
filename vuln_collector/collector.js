require('dotenv').config();
const config = require('./config');
const db = require('./lib/db');
const logger = require('./lib/logger');

const nvd = require('./sources/nvd');
const mitre = require('./sources/mitre-cve');
const cisaKev = require('./sources/cisa-kev');
const github = require('./sources/github-advisories');
const translator = require('./lib/translator');

const SOURCES = [
  { name: 'NVD', module: nvd, interval: config.intervals.nvd },
  { name: 'MITRE', module: mitre, interval: config.intervals.mitre },
  { name: 'CISA_KEV', module: cisaKev, interval: config.intervals.cisaKev },
  { name: 'GitHub', module: github, interval: config.intervals.github }
];

// 지수 백오프 상태
const backoff = {};
// 동시 실행 방지 플래그
const running = {};
// 타이머 핸들 (shutdown 시 정리용)
const timers = [];

async function runSource(source) {
  const key = source.name;

  // 이미 실행 중이면 스킵
  if (running[key]) {
    logger.warn(key, '이전 수집이 아직 실행 중 - 스킵');
    return;
  }

  running[key] = true;
  try {
    await source.module.collect();
    // 성공 시 백오프 리셋
    backoff[key] = { delay: config.retry.initialDelay, consecutive: 0 };
  } catch (err) {
    if (!backoff[key]) backoff[key] = { delay: config.retry.initialDelay, consecutive: 0 };
    backoff[key].consecutive++;
    const currentDelay = Math.min(
      backoff[key].delay * Math.pow(config.retry.factor, backoff[key].consecutive - 1),
      config.retry.maxDelay
    );

    logger.error(key, `수집 실패: ${err.message}`);
    logger.warn(key, `${Math.round(currentDelay / 1000)}초 후 재시도 예정 (연속 실패: ${backoff[key].consecutive}회)`);

    // 재시도 스케줄
    const retryTimer = setTimeout(() => runSource(source), currentDelay);
    timers.push(retryTimer);
  } finally {
    running[key] = false;
  }
}

let translationRunning = false;

async function runTranslation() {
  if (translationRunning) return;
  translationRunning = true;
  try {
    await translator.translateBatch(50);
  } catch (err) {
    logger.error('translator', `번역 배치 실패: ${err.message}`);
  } finally {
    translationRunning = false;
  }
}

function startScheduler() {
  logger.info('MAIN', '취약점 수집기 시작');
  logger.info('MAIN', `수집 소스: ${SOURCES.map(s => s.name).join(', ')}`);
  logger.info('MAIN', `초기 수집 범위: ${config.initialFetchDays}일`);

  for (const source of SOURCES) {
    backoff[source.name] = { delay: config.retry.initialDelay, consecutive: 0 };
    running[source.name] = false;

    // 시작 시 즉시 1회 수집 (소스별 5초 간격으로 시작)
    const initialDelay = SOURCES.indexOf(source) * 5000;
    const initTimer = setTimeout(() => runSource(source), initialDelay);
    timers.push(initTimer);

    // 이후 인터벌로 반복
    const intervalTimer = setInterval(() => runSource(source), source.interval);
    timers.push(intervalTimer);

    logger.info('MAIN', `${source.name}: ${source.interval / 1000 / 60}분 간격, ${initialDelay / 1000}초 후 시작`);
  }

  // 번역 스케줄: 30초 후 시작, 이후 1시간 간격
  const transInitTimer = setTimeout(() => runTranslation(), 30 * 1000);
  timers.push(transInitTimer);
  const transIntervalTimer = setInterval(runTranslation, 60 * 60 * 1000);
  timers.push(transIntervalTimer);
  logger.info('MAIN', '번역: 30초 후 시작, 이후 60분 간격');
}

// graceful shutdown
let shuttingDown = false;

async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info('MAIN', `${signal} 수신 - 종료 중...`);

  // 모든 타이머 정리
  for (const t of timers) {
    clearTimeout(t);
    clearInterval(t);
  }

  await db.close();
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

process.on('uncaughtException', (err) => {
  logger.error('MAIN', `미처리 예외: ${err.message}`);
  logger.error('MAIN', err.stack);
  shutdown('uncaughtException');
});

process.on('unhandledRejection', (err) => {
  logger.error('MAIN', `미처리 Promise 거부: ${err.message || err}`);
});

// 시작
startScheduler();
