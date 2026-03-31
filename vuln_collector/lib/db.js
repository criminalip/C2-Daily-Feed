const mysql = require('mysql2/promise');
const config = require('../config');
const logger = require('./logger');

let pool = null;

function getPool() {
  if (!pool) {
    pool = mysql.createPool(config.db);
    logger.info('DB', `커넥션 풀 생성 (${config.db.host}/${config.db.database})`);
  }
  return pool;
}

async function query(sql, params) {
  const [rows] = await getPool().execute(sql, params);
  return rows;
}

async function getConnection() {
  return getPool().getConnection();
}

async function close() {
  if (pool) {
    await pool.end();
    pool = null;
    logger.info('DB', '커넥션 풀 종료');
  }
}

module.exports = { query, getConnection, close };
