function timestamp() {
  return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

function log(source, level, message) {
  console.log(`[${timestamp()}] [${source}] [${level}] ${message}`);
}

module.exports = {
  info: (source, msg) => log(source, 'INFO', msg),
  warn: (source, msg) => log(source, 'WARN', msg),
  error: (source, msg) => log(source, 'ERROR', msg)
};
