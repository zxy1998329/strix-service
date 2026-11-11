# Docker Desktop 本机部署

在本目录运行，Docker Desktop 使用 Linux 容器：

```powershell
docker desktop start
docker compose -f compose.desktop.yaml up -d --build
docker compose -f compose.desktop.yaml ps
```

- 员工页面：http://127.0.0.1:8080/
- 管理页面：http://127.0.0.1:8080/admin
- 初始管理员密码：沿用代码默认值 `296419`，登录后可修改。
- 员工使用 6 位数字工号登录。

API、Worker 和演示目标分别运行于三个容器。页面只发布到本机回环地址；数据保存于 `strix-local-data` 卷，重建容器后保留。初始扫描关闭，需要在管理员页面配置模型并启用。部署本身不提交扫描，也不测试付费模型。

演示目标为 `http://172.30.88.10:8765/`，位于 Docker 内部网络 `strix-local-sandbox`。当前网络用于本机演示；访问其他目标需要另外配置授权范围和受控网络。

查看日志和停止服务：

```powershell
docker compose -f compose.desktop.yaml logs --tail 100 api worker
docker compose -f compose.desktop.yaml stop
```

更新源码后重新运行 `up -d --build`。不要使用 `down -v`，该命令会删除本部署的数据卷。

此文件与 `compose.desktop.yaml` 配套；旧的 `compose.local.yaml` 依赖预先创建的资源和本地密钥文件，本部署不需要这些文件。
