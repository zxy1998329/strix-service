# 在本目录运行；保留现有持久化数据卷。
docker compose --env-file .local.env -f compose.local.yaml up -d --no-deps api worker
Invoke-RestMethod 'http://127.0.0.1:8080/healthz'
