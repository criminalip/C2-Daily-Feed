CREATE DATABASE IF NOT EXISTS vuln_collector CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE vuln_collector;

-- 메인 취약점 테이블
CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cve_id VARCHAR(20) NOT NULL UNIQUE,
  title VARCHAR(500),
  title_ko VARCHAR(500),
  description TEXT,
  description_ko TEXT,
  severity ENUM('CRITICAL','HIGH','MEDIUM','LOW','NONE') DEFAULT 'NONE',
  cvss_v3_score DECIMAL(3,1),
  cvss_v3_vector VARCHAR(200),
  published_date DATETIME,
  modified_date DATETIME,
  first_seen DATETIME NOT NULL,
  last_updated DATETIME NOT NULL,
  is_kev BOOLEAN DEFAULT FALSE,
  kev_due_date DATE,
  exploit_available BOOLEAN DEFAULT FALSE,
  patch_available BOOLEAN DEFAULT FALSE,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_severity (severity),
  INDEX idx_published (published_date),
  INDEX idx_cvss (cvss_v3_score),
  INDEX idx_kev (is_kev),
  INDEX idx_last_updated (last_updated)
);

-- CWE 테이블 (N:M 관계)
CREATE TABLE IF NOT EXISTS cwe_entries (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cwe_id VARCHAR(20) NOT NULL UNIQUE,
  name VARCHAR(300)
);

CREATE TABLE IF NOT EXISTS vulnerability_cwes (
  vulnerability_id INT NOT NULL,
  cwe_id INT NOT NULL,
  PRIMARY KEY (vulnerability_id, cwe_id),
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  FOREIGN KEY (cwe_id) REFERENCES cwe_entries(id) ON DELETE CASCADE
);

-- 영향받는 제품 테이블
CREATE TABLE IF NOT EXISTS affected_products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  vulnerability_id INT NOT NULL,
  vendor VARCHAR(200),
  product VARCHAR(200),
  versions VARCHAR(500),
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  INDEX idx_vendor_product (vendor, product),
  UNIQUE INDEX idx_vuln_vendor_product (vulnerability_id, vendor(100), product(100))
);

-- 참조 링크 테이블
CREATE TABLE IF NOT EXISTS reference_links (
  id INT AUTO_INCREMENT PRIMARY KEY,
  vulnerability_id INT NOT NULL,
  url VARCHAR(1000) NOT NULL,
  source VARCHAR(200),
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- 수집 소스 테이블
CREATE TABLE IF NOT EXISTS vulnerability_sources (
  vulnerability_id INT NOT NULL,
  source VARCHAR(20) NOT NULL,
  source_url VARCHAR(500),
  collected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (vulnerability_id, source),
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- 태그 테이블
CREATE TABLE IF NOT EXISTS tags (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS vulnerability_tags (
  vulnerability_id INT NOT NULL,
  tag_id INT NOT NULL,
  PRIMARY KEY (vulnerability_id, tag_id),
  FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- 알림 이력 테이블
CREATE TABLE IF NOT EXISTS alert_history (
  id INT AUTO_INCREMENT PRIMARY KEY,
  cve_id VARCHAR(20) NOT NULL UNIQUE,
  categories VARCHAR(100),
  alerted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_alerted_at (alerted_at)
);

-- 수집기 상태 테이블
CREATE TABLE IF NOT EXISTS collector_state (
  source VARCHAR(20) PRIMARY KEY,
  last_successful_fetch DATETIME,
  last_cursor TEXT,
  extra_state JSON,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
