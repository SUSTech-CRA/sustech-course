# API 限流系统设计

本文档描述 ncesnext 的三层限流架构：nginx 洪水闸（L1）、FastAPI 应用层限流（L2）、Turnstile 人机验证豁免通道（L3）。修改配额、身份识别或挑战流程前请先对照本文。

## 总览

```
客户端
  │
  ▼
边缘 nginx（写入 X-Real-IP）
  │
  ▼
本机 nginx ── L1: limit_req 按 IP 洪水闸（20r/s api / 2r/s auth）→ 超限直接 429
  │              realip 模块从 X-Real-IP 还原真实客户端 IP
  ▼
FastAPI ──── L2: RateLimitMiddleware 按 用户/IP 分键的分钟级配额 → 超限 429 + challenge 标记
  │
  ▼
前端拦截器 ─ L3: 收到带 challenge 标记的 429 → 弹 Turnstile Modal → 换取 20 分钟豁免凭证 → 自动重试
```

设计原则：

- **L1 管洪水，L2 管公平，L3 给真人留出口。** 校园 NAT 下大量用户共享出口 IP，所以 nginx 的 per-IP 阈值刻意放宽（只拦洪水），精细配额放在应用层按用户分键。
- **零新增依赖、零 DB。** 计数器是进程内存，豁免凭证是无状态签名 token（itsdangerous，复用邮箱验证同一套 `create_timed_token` 基建）。
- **可整体关闭。** 开发时设 `RATE_LIMIT_ENABLED=false` 即可完全绕过 L2/L3；L1 只存在于部署环境的 nginx，本地开发天然没有。

## 身份标记：登录 vs 匿名

核心函数 `identity_key()`（`backend/app/core/rate_limit.py`）：

| 用户状态 | 识别方式 | 限流键 |
|---|---|---|
| 已登录 | 解码 `Authorization: Bearer` 中的 access JWT（仅验签名和类型，**不查 DB**），取 `sub` | `user:{user_id}` |
| 匿名 / token 无效或过期 | `X-Real-IP` 请求头，缺失时回退 `request.client.host` | `ip:{addr}` |

要点：

- 登录用户按**账号**分键，切换 IP、多设备共用同一配额；NAT 后面的多个登录用户互不影响。
- 匿名用户按 **IP** 分键——匿名场景下 IP 是唯一不能被客户端零成本伪造的标识，session/cookie 作限流键会被"不带 cookie"直接绕过。
- token 无效（过期、伪造）不报错，只是静默降级为按 IP 计——限流层不做认证，认证仍由路由层的依赖负责。
- `X-Real-IP` 由本机 nginx 的 `proxy_set_header X-Real-IP $remote_addr` 写入，而 `$remote_addr` 已被 realip 模块还原为真实客户端 IP。**信任链前提**：uvicorn 端口（示例配置为 3001，开发 8000）不能对外直连，否则任何人可伪造 X-Real-IP 绕过匿名限流。

## L2 计数与判定（FastAPI 中间件）

`RateLimitMiddleware`（`backend/app/core/rate_limit.py`），在 `main.py` 中**先于 CORSMiddleware 注册**，使 CORS 成为最外层——429 响应也能带上 CORS 头，且 CORS 预检（OPTIONS）被 CORS 中间件短路、不进计数。

### 判定流程（每个请求）

1. **跳过**：功能关闭、路径不以 `/api/` 开头、或路径在豁免名单 `EXEMPT_PATHS` 中，直接放行。豁免名单：
   - `/api/health`、`/api/docs`、`/api/openapi.json`
   - `/api/v1/challenge` —— 解封端点本身
   - `/api/v1/auth/public-config` —— 挑战 Modal 需要它拿 Turnstile site key。**这两条豁免是死锁修复的关键**：超限用户必须还能走通"自证解封"的完整链路，否则 429 会把解封通道也堵死。
2. **读桶**：按身份键计数，登录用户上限 `RATE_LIMIT_USER_PER_MINUTE`，匿名 `RATE_LIMIT_ANON_PER_MINUTE`。
3. **写桶**：方法为 POST/PUT/PATCH/DELETE 时，额外对 `write:{key}` 计数，上限 `RATE_LIMIT_WRITE_PER_MINUTE`。例外：`/api/v1/auth/` 前缀（登录/注册等匿名 POST）不占写桶——它们由 nginx 的 auth zone 单独限流。
4. **豁免凭证**：任一桶超限时，检查 `X-Challenge-Token` 请求头（见 L3）。凭证有效则放行，无效才拒绝。豁免检查放在超限之后，正常流量零开销。
5. **拒绝**：返回 429，JSON 为 `{"detail": "请求过于频繁，请稍后再试", "challenge": "turnstile"}`（`challenge` 字段仅在 `RATE_LIMIT_CHALLENGE_ENABLED=true` 时携带），响应头 `Retry-After: 60`。前端靠 `challenge` 字段区分"可自助解封的应用层 429"和"nginx 层 429"。

### 计数器实现

`SlidingWindowLimiter`：`dict[key, deque[时间戳]]` + 线程锁，60 秒滑动窗口，每个窗口周期顺带清理一次陈旧键。**计数是进程内的**，这带来一个重要语义：

- 生产 systemd 以 uvicorn **4 workers** 运行，4 个进程各自独立计数。
- **高并发洪水**会近似均匀打到 4 个 worker，全局有效上限 ≈ 配置值 × 4。
- **单个用户的串行请求**（正常浏览、手动刷新）几乎总是落在同一个 worker 上——内核在 accept 时偏向唤醒刚空闲的进程——所以真实用户感受到的上限 ≈ 配置值 × 1。
- 这个不对称对防御有利（单个激进客户端在配置值附近就被拦下），但调参时要记住：**默认值是按"洪水 ×4"校准的，对真实串行用户没有 ×4 余量**。如果收到"正常浏览也弹验证"的反馈，优先调高 `RATE_LIMIT_ANON_PER_MINUTE`，而不是怀疑逻辑有 bug。
- 若未来改 worker 数，需同步重估各配额；若引入 Redis（目前刻意不引入），换掉 `SlidingWindowLimiter` 即可，键与判定逻辑不变。

## L3 豁免通道：429 → Turnstile → 签名凭证

### 后端

- `POST /api/v1/challenge`（`backend/app/api/v1/challenge.py`）：用 `verify_turnstile()` 校验前端提交的 Turnstile token，通过后签发豁免凭证：

  ```
  exempt_token = create_timed_token(identity_key(request), salt="rate-limit-exempt")
  ```

  凭证内容就是**申请者当时的身份键**（`user:42` 或 `ip:1.2.3.4`），由 itsdangerous 签名并含时间戳，无服务端状态，多 worker 天然一致。
- 校验（`_is_exempt`）：验签、验时效（`RATE_LIMIT_EXEMPT_MINUTES`，默认 20 分钟）、且解出的身份键必须**等于当前请求的身份键**——凭证不可转借：换了 IP 的匿名用户、或把凭证复制给别人，都会失效。
- 注意 `verify_turnstile` 的行为（`backend/app/services/auth_service.py`）：`RECAPTCHA_SECRET_KEY` **未配置时直接放行**（返回 True）。这是开发便利（本地无需申请 Turnstile 密钥），生产必须配置该密钥，否则挑战形同虚设。字段名是历史遗留，实际存的是 **Turnstile** 的 secret。

### 前端

流程分布在四个文件：

1. **`api/client.ts` 响应拦截器**：捕获 429 且 `data.challenge === 'turnstile'` → `await useChallengeStore.getState().request()` 等待挑战完成 → 标记 `_challengeRetried` 后原样重发一次。重发再失败只 toast（3 秒节流），不再弹窗，防止重试风暴。nginx 层 429 没有 `challenge` 字段，直接走 toast 分支。
2. **`stores/challengeStore.ts`**：单飞（single-flight）——并发多个 429 共享同一个 pending Promise，只弹一个 Modal；成功全部继续，取消全部回落。
3. **`components/auth/ChallengeModal.tsx`**：打开时经 react-query 拉 `/auth/public-config` 取 site key（该端点已在后端豁免名单中）。四个渲染分支：加载中 Spin / 加载失败 Alert+重试 / 无 site key 时"继续访问"按钮（提交 null token，对应后端未配密钥的放行逻辑）/ 正常渲染 `TurnstileWidget`。匿名用户额外提示"登录用户享有更高配额"。
4. **`api/challenge.ts`**：`solveChallenge` 用**独立的裸 axios 实例**（不带任何拦截器）——挑战请求自身再触发挑战流程会死锁。

凭证的保存与携带（`api/client.ts`）：

- 成功后 `setChallengeExempt(token, expires_in)` 写入模块变量 + `sessionStorage`（key `ncesnext-challenge-exempt`），刷新页面不丢，关标签页即弃。
- 请求拦截器在凭证未过期时自动附加 `X-Challenge-Token` 头；过期由前端时间戳预判 + 后端签名时效双重保证。

另有一处配套防御：`refreshAuthLogic` 仅在 refresh 请求收到 **401** 时才登出；429/网络错误/5xx 只让当次请求失败、保留会话——否则限流期间恰逢 token 刷新会把用户踢下线。

## L1：nginx 洪水闸

示例见 `scripts/nginx/backend.conf`（实际部署的阈值以服务器上的配置为准，改完 `nginx -t && systemctl reload nginx`）：

```nginx
# http 上下文（文件顶部）
limit_req_zone $binary_remote_addr zone=nces_api:10m  rate=20r/s;
limit_req_zone $binary_remote_addr zone=nces_auth:10m rate=2r/s;

location /api/v1/auth/ {
    limit_req zone=nces_auth burst=10 nodelay;
    limit_req_status 429;
    # ... proxy_pass 同 /api/
}
location /api/ {
    limit_req zone=nces_api burst=40 nodelay;
    limit_req_status 429;
    # ...
}
```

- 键是 `$binary_remote_addr`（真实客户端 IP，realip 模块在 limit_req 之前的阶段执行，顺序正确）。计数在 nginx 共享内存 zone 中，**不受后端多 worker 影响，是精确的全局计数**。
- auth 路径单独收紧到 2r/s：登录/注册是暴力破解的主要目标，且正常用户不会高频访问。
- nginx 429 返回的是 nginx 自己的错误页，无 `challenge` 字段、无豁免通道——这是有意的：能触发 20r/s 洪水闸的流量不值得给人机验证的机会。
- 双层 nginx 信任链：边缘 nginx（内网网段，示例配置中为 `EDGE_NGINX_SUBNET`）写入 X-Real-IP → 本机 nginx `set_real_ip_from` + `real_ip_header X-Real-IP` 还原。**边缘 nginx 必须覆盖（而非透传）客户端自带的 X-Real-IP 头**，否则 IP 可伪造。

## 配置项一览

全部在 `backend/app/config.py`，可用环境变量或 `.env` 覆盖：

| 配置 | 默认 | 说明 |
|---|---|---|
| `RATE_LIMIT_ENABLED` | `true` | L2 总开关，`false` 时中间件直接放行（开发时关这个） |
| `RATE_LIMIT_ANON_PER_MINUTE` | `20` | 匿名读配额 / 分钟 / 进程（4 worker 下洪水场景 ≈ 80） |
| `RATE_LIMIT_USER_PER_MINUTE` | `60` | 登录读配额 / 分钟 / 进程 |
| `RATE_LIMIT_WRITE_PER_MINUTE` | `8` | 写操作配额（读桶之外额外计数） |
| `RATE_LIMIT_SUGGEST_PER_MINUTE` | `40` | 搜索建议独立配额，不占用通用读配额 |
| `RATE_LIMIT_CHALLENGE_ENABLED` | `true` | 429 是否携带 `challenge` 标记（即是否给前端弹 Turnstile 的机会） |
| `RATE_LIMIT_EXEMPT_MINUTES` | `20` | 豁免凭证有效期 |
| `RECAPTCHA_SECRET_KEY` | — | Turnstile secret（名字是历史遗留）；**未配置时挑战无条件通过** |

常用组合：

- 本地开发不想被限流打扰：`RATE_LIMIT_ENABLED=false`。
- 想测限流但跳过真实 Turnstile：保持 enabled，把 `RECAPTCHA_SECRET_KEY` 留空，Modal 会显示"继续访问"按钮一键解封。
- 想测 429 提示但不弹窗：`RATE_LIMIT_CHALLENGE_ENABLED=false`。

## 已知边界与未做的事

- **IPv6 未按 /64 分键**：nginx zone 和应用层目前都按单个地址计数。若入口开放 IPv6，攻击者可在自己的 /64 前缀内轮换地址稀释限流。入口仅 IPv4 时无此问题。
- **计数器阈值膨胀**：见上文多 worker 一节；接受现状，Redis 方案等出现第二个 Redis 使用场景再考虑。
- **豁免期内计数器仍在累积**：持凭证用户放行时不清空 deque，凭证到期后若仍超速会立即再次 429（需重新挑战）。这是预期行为。
- **nginx auth zone 与 public-config**：`/api/v1/auth/public-config` 在应用层豁免，但仍受 nginx auth zone（2r/s）约束。极端情况下 Modal 拉 site key 可能被 nginx 429，此时 Modal 显示错误 + 重试按钮兜底，不构成死锁。

## 相关文件

| 层 | 文件 |
|---|---|
| L2 中间件 + 计数器 + 豁免校验 | `backend/app/core/rate_limit.py` |
| 中间件注册（顺序敏感） | `backend/app/main.py` |
| 挑战端点 | `backend/app/api/v1/challenge.py`（注册于 `backend/app/api/v1/__init__.py`） |
| 请求/响应 schema | `backend/app/schemas/auth.py` |
| 配置 | `backend/app/config.py` |
| 签名 token 基建 | `backend/app/core/security.py`（`create_timed_token` / `verify_timed_token`） |
| Turnstile 服务端校验 | `backend/app/services/auth_service.py`（`verify_turnstile`） |
| 前端拦截器 + 凭证存取 | `frontend/src/api/client.ts` |
| 挑战单飞状态 | `frontend/src/stores/challengeStore.ts` |
| 挑战 Modal | `frontend/src/components/auth/ChallengeModal.tsx` |
| 挑战专用 axios 实例 | `frontend/src/api/challenge.ts` |
| Turnstile 组件（复用既有） | `frontend/src/components/auth/TurnstileWidget.tsx` |
| L1 nginx 示例 | `scripts/nginx/backend.conf` |
