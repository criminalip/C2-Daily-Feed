module.exports = {
  db: {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'vuln_collector',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'vuln_collector',
    connectionLimit: 5,
    charset: 'utf8mb4'
  },

  // API 키
  nvdApiKey: process.env.NVD_API_KEY || '',
  githubToken: process.env.GITHUB_TOKEN || '',

  // 소스별 폴링 간격 (ms)
  intervals: {
    nvd: 2 * 60 * 60 * 1000,       // 2시간
    mitre: 2 * 60 * 60 * 1000,     // 2시간
    cisaKev: 6 * 60 * 60 * 1000,   // 6시간
    github: 4 * 60 * 60 * 1000     // 4시간
  },

  // 초기 수집 범위 (일)
  initialFetchDays: 7,

  // 재시도 설정
  retry: {
    initialDelay: 30 * 1000,   // 30초
    maxDelay: 30 * 60 * 1000,  // 30분
    factor: 2
  },

  // Slack 알림 설정
  slack: {
    botToken: process.env.SLACK_BOT_TOKEN || '',
    channel: process.env.SLACK_CHANNEL || 'C07SD7AEJ6L',
    alertCvssThreshold: 8.0
  }
};
