module.exports = {
  apps: [{
    name: 'api-jhd',
    script: 'E:/Dev/josephhansen-dev-api/server.js',
    cwd: 'E:/Dev/josephhansen-dev-api',
    instances: 1,
    exec_mode: 'fork',
    watch: false,
    max_memory_restart: '500M',
    env: {
      NODE_ENV: 'production',
      PORT: 9640
    },
    env_file: '.env',
    // PM2 will automatically load .env file
    dotenv: true,
    // Error handling
    error_file: './logs/err.log',
    out_file: './logs/out.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    // Restart options
    autorestart: true,
    max_restarts: 10,
    min_uptime: '10s'
  }]
};
