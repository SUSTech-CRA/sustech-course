# nginx 配置示例

三份站点配置，对应推荐的两层部署拓扑，外加一份开发机配置。文件中的地址、路径为示例值，部署前按实际环境替换：

| 占位 | 含义 |
|---|---|
| `BACKEND_NGINX_HOST` | 后端机内网地址（`edge.conf`） |
| `EDGE_NGINX_SUBNET` | 边缘机所在内网网段，后端机只信任该网段传来的 `X-Real-IP`（`backend.conf`） |
| `/opt/ncesnext/frontend/dist` | 前端构建产物目录 |
| `/var/lib/ncesnext` | `UPLOAD_FOLDER` 的父目录（存量上传文件，新上传写入 R2） |
| `/opt/legacy-course-app/app` | 老应用静态目录，仅从老站迁移、老点评引用 `/static/...` 时需要 |
| `ncesnext.com` / 证书路径 | 你的域名与证书 |

| 文件 | 机器 | 职责 |
|---|---|---|
| `edge.conf` | 公网边缘机 | TLS 终止、HTTP→HTTPS、反代后端机 `:8080`、`/assets` `/uploads` 磁盘缓存 |
| `backend.conf` | 后端机（8080） | 路径分流（API → uvicorn `127.0.0.1:3001`）、静态读盘、SPA fallback、粗粒度限流 |
| `dev.conf` | 开发机 | TLS 终止后转发 Vite dev server（8001），支持 HMR websocket |

单机部署时可以只用 `backend.conf`：在其中加上 TLS 配置并监听 443，去掉 `set_real_ip_from EDGE_NGINX_SUBNET`。

放置方式：拷贝到对应机器的 `/etc/nginx/conf.d/` 或 `sites-available/` + 软链 `sites-enabled/`，然后 `nginx -t && systemctl reload nginx`。

## 全局依赖（nginx.conf http 块）

- 边缘机需要缓存区定义（`edge.conf` 引用 `static_cache`，不重复定义）：

  ```nginx
  proxy_cache_path /var/cache/nginx/static levels=1:2
      keys_zone=static_cache:100m max_size=5g inactive=7d use_temp_path=off;
  ```

- gzip/brotli 在各站点配置内显式设置，不依赖 nginx.conf 的全局压缩配置（裸 `gzip on;` 不带 `gzip_types` 时只压 text/html）。需要安装 ngx_brotli 模块；没有该模块时删除 `brotli*` 指令。
- 同一台 nginx 若加载多份本目录配置，`map $http_upgrade $connection_upgrade` 只能保留一份。

## 设计要点

- **Cache-Control 单一来源在后端层**，边缘层只做 `proxy_cache` 与 `X-Cache-Status`。nginx 的 `add_header` 是追加不是覆盖，两层都加头会得到多个互相冲突的 Cache-Control。
  - `/assets/`：一年 + immutable（Vite 产物文件名带内容 hash）。
  - `/uploads/`：30 天（随机文件名不复用）。
  - `/index.html`：no-cache。SPA 关键项，否则浏览器启发式缓存旧 index，部署后引用已删除的 hashed chunk 会白屏。
- 边缘层 `/assets|/uploads` 带 `proxy_cache_valid 404 1m` 负缓存与 `proxy_cache_revalidate`，静态转发同样补 `X-Real-IP` / `X-Forwarded-*`。
- **真实 IP 信任链**：边缘层用 `proxy_set_header X-Real-IP $remote_addr` **覆盖**客户端自带的同名头；后端层 `set_real_ip_from` 只信任边缘网段与本机。后端机的 8080 与 uvicorn 端口都不能对公网开放，否则 IP 可被伪造，应用层限流失效。
- 安全头：`/uploads/`、`/assets/`、`index.html` 加 `X-Content-Type-Options: nosniff`；`index.html` 加 `X-Frame-Options: SAMEORIGIN`。
- `client_max_body_size` 两层统一 50M（边缘层先拦，后端层配更大值不会生效）。
- 限流：后端层 `limit_req` 只作洪水闸，精细配额在应用层按用户/IP 分键，见 `docs/rate-limiting.md`。
- WebSocket：应用当前无 WS，`Upgrade/Connection` 头全链路预留；dev 层 Vite HMR 必需，并拉长 `proxy_read_timeout`。
- `/cdn-cgi/trace` 是模仿 Cloudflare trace 格式的诊断端点，可按需删除。

## 部署后验证

```bash
nginx -t

# 压缩生效（应看到 content-encoding: br；改 gzip 验证 gzip 通路）
curl -sI --compressed https://ncesnext.com/assets/<某个js> | grep -i 'content-encoding\|vary'

# 缓存头正确且只有一个 Cache-Control
curl -sI https://ncesnext.com/assets/<某个js> | grep -i 'cache-control\|x-cache-status'
curl -sI https://ncesnext.com/ | grep -i cache-control          # 应为 no-cache

# 边缘缓存命中（第二次应为 HIT）
curl -sI https://ncesnext.com/assets/<某个js> | grep -i x-cache-status
```

## 前端发版顺序

**先同步新 assets，最后替换 index.html**（一次性 `rsync --delete` 没有这个保证）。若新 index 先可见而对应 chunk 还没就位，用户请求会得到 404，且被边缘层负缓存 1 分钟，期间前端的 preloadError 自动刷新也无法恢复。哈希文件名下“assets 先行”永远安全；旧 assets 可延迟清理或保留最近一版。
