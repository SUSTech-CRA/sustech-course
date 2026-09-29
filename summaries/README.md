# 课程公开点评 AI 总结

总结由每日离线任务生成，课程详情 API 只读 `course_review_summary` 派生表，用户请求不会同步调用 LLM。
输入严格使用游客可见口径：未隐藏、未屏蔽且 `only_visible_to_student=false` 的点评；不查询或发送作者字段。

## 首次部署

1. 在共用数据库手工创建独立派生表（必须先建表，再部署会读取该表的新后端）：

   ```bash
   cd backend
   mysql -u <user> -p <database> < scripts/sql/create_course_review_summary.sql
   ```

   不运行 Alembic，不修改任何老表。若需回滚展示代码，表可以保留；它不会被老应用读取。

2. 在 `backend/.env` 配置：

   ```dotenv
   LLM_BASE_URL=https://api.deepseek.com
   LLM_API_KEY=<DeepSeek API key>
   LLM_MODEL=deepseek-v4-pro
   COURSE_SUMMARY_MIN_PUBLIC_REVIEWS=10
   # 可选：LLM_TIMEOUT_SECONDS=180
   ```

   `LLM_API_KEY` 为空时任务正常退出且不写库，站点其余功能不受影响。

3. 先 dry-run 检查候选，再少量生成。`--commit` 才会调用 API/写库：

   ```bash
   python scripts/generate_summaries.py --min-reviews 41
   python scripts/generate_summaries.py --min-reviews 41 --commit
   ```

4. 部署每日 timer：

   ```bash
   sudo cp ../summaries/systemd/ncesnext-course-summary.{service,timer} /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now ncesnext-course-summary.timer
   sudo systemctl start ncesnext-course-summary.service
   journalctl -u ncesnext-course-summary.service -n 100
   ```

## 增量、隐藏与重生成

- 指纹覆盖 prompt 版本和实际公开输入内容/评分。点评新增、修改、删除、隐藏、屏蔽或切换为仅学生可见后，下一轮会重生成；模型名变化也会重生成。
- timer 使用 `--prune-stale`，课程跌破阈值后会删除旧派生摘要，避免继续展示过时内容。手动高阈值试跑不要加这个参数，以免按测试阈值清理正式摘要。
- `--force` 强制重生成；`--course-id ID` 可重复指定课程；`--limit N` 限制本轮生成数量。
- 管理员可调用 `PATCH /api/v1/admin/course-summaries/{course_id}/visibility`，body 为
  `{"is_hidden": true}`（恢复展示传 `false`）。紧急情况下也可直接执行：

  ```sql
  UPDATE course_review_summary SET is_hidden = 1 WHERE course_id = <id>;
  ```

  恢复展示设为 `0`。隐藏不会阻止离线刷新，后续生成会保留 `is_hidden` 状态。

## 回滚

- 停用生成：`sudo systemctl disable --now ncesnext-course-summary.timer`。
- 停止展示：回滚后端/前端代码即可；表可原样保留，避免丢失已付费生成的数据。
- 若确认永久删除：先停 timer 并回滚读取代码，再手工 `DROP TABLE course_review_summary`。
