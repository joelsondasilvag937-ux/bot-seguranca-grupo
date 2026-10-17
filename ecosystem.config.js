module.exports = {
  apps: [
    {
      name: "bot-seguranca-grupo",
      script: "./index.stable.js",
      args: [],
      instances: 1,
      autorestart: true,
      watch: false,
      max_restarts: 10,
      restart_delay: 5000,
      env: {
        NODE_ENV: "production"
      },
      env_production: {
        NODE_ENV: "production"
      },
      // log files
      output: "./logs/out.log",
      error: "./logs/error.log",
      merge_logs: true
    }
  ]
};
