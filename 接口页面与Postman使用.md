# 接口页面与 Postman 调试（v0.2.1）

直接打开 <http://127.0.0.1:8080/api-guide>，或登录后点击左侧「接口文档」。员工和管理员都能使用，访问权限与登录账号一致。

## 使用流程

1. 点击「生成 7 天 API 令牌」。这是本服务的调用凭据，不是模型 Key 或管理员密码。每账号最多 10 个有效令牌，可在下方撤销。
2. 从下拉框选择黑盒、白盒、进度查询、报告或取消接口。
3. 按需填写服务地址、黑盒目标、任务 ID。
4. 点击「复制 cURL 到 Postman」。打开 Postman，选择 Import → Raw text（部分版本直接粘贴到 Import 输入区），粘贴并导入。
5. 白盒接口导入后，在 Body → form-data 的 project 字段重新选择 ZIP。不要手动设置 multipart Content-Type，Postman 会生成 boundary。
6. 提交返回 HTTP 202 和 id，再使用查询接口检查状态，报告就绪后下载。

如只分享示例，请选择「复制无密钥模板」。含真实令牌的 cURL 不应分享。令牌明文仅生成时返回一次，数据库仅保存摘要；刷新或退出后页面不再保留明文。退出登录不自动撤销已签发令牌。

也可以「下载 Postman 集合」。导出包含 5 个请求和 base_url、api_token、job_id、target 变量；出于凭据保护考虑，导出的 api_token 为空，需要自行填写。集合文件已另存本目录 Strix.postman_collection.json，可直接导入。

## 接口列表

| 方法 | 路径 | 用途 |
|---|---|---|
| POST | /v1/scans/blackbox | JSON 提交授权 HTTP(S) 根地址 |
| POST | /v1/scans/whitebox | multipart/form-data 上传 ZIP |
| GET | /v1/scans/{id} | 查询进度与报告就绪状态 |
| GET | /v1/scans/{id}/report | Markdown 报告；format=json 返回 JSON |
| POST | /v1/scans/{id}/cancel | 取消任务 |

页面展示每个接口的必填项、字段类型、成功响应及常见错误码。示例响应为示意数据，实际扫描以任务查询结果为准。

## 权限与费用

- 员工令牌只访问自己的任务；管理员令牌能访问全部任务。
- API 请求显式携带 Authorization: Bearer 令牌，不需要浏览器 Cookie、CSRF 或 PowerShell。
- 网页签发令牌需有效登录及 CSRF，管理员停用员工会撤销其 API 令牌；修改管理员密码也撤销管理员令牌。
- 令牌过期、撤销或账号停用后调用失败；错误令牌不会继承浏览器登录权限。
- 生成令牌、复制示例和下载集合都不会提交扫描或调用付费模型。主动提交检测后，模型费用与网页扫描一致。
- 必须由管理员启用扫描、配置模型并登记目标范围；接口不会绕过网络策略和目标白名单。

## 交付与升级

当前主镜像 strix-service:0.2.1，离线包位于上一级目录 strix-web-0.2.1-offline.tar。部署方式与上一版相同，使用原数据卷可保留账号、模型配置和任务，新增令牌表按需初始化。Compose 文件已更新镜像标签。
