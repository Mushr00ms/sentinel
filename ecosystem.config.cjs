/**
 * PM2 Ecosystem Configuration for Sentinel
 *
 * Usage:
 *   pm2 start ecosystem.config.cjs
 *   pm2 logs sentinel
 *   pm2 status
 */

module.exports = {
  apps: [
    {
      name: "sentinel",
      script: "node",
      args: "--import tsx/esm sentinel/index.ts",
      cwd: "/home/cr0wn/sentinel",
      env_file: ".env",
      watch: false,
      autorestart: true,
      max_restarts: 20,
      restart_delay: 5000,
      min_uptime: "10s",
      kill_timeout: 10000,
      log_date_format: "YYYY-MM-DD HH:mm:ss",
      out_file: "./logs/sentinel.out.log",
      error_file: "./logs/sentinel.err.log",
      merge_logs: true,
      max_memory_restart: "2G",
      env: {
        NODE_ENV: "production",
        NODE_OPTIONS: "--max-old-space-size=2048",
      },
    },
  ],
};
