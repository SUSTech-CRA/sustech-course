-- NCES Next 公开点评 AI 总结派生表。
--
-- 必须在部署包含 CourseReviewSummary ORM 的后端代码之前手工执行；不走 Alembic，
-- 不修改任何老表。course_id 刻意不加外键，避免影响共库期间老应用删除课程的行为。

CREATE TABLE IF NOT EXISTS `course_review_summary` (
  `course_id` int(11) NOT NULL,
  `summary_json` json NOT NULL,
  `model` varchar(100) NOT NULL,
  `prompt_version` varchar(32) NOT NULL,
  `source_fingerprint` varchar(64) NOT NULL,
  `source_review_count` int(11) NOT NULL,
  `generated_at` datetime NOT NULL,
  `prompt_tokens` int(11) DEFAULT NULL,
  `completion_tokens` int(11) DEFAULT NULL,
  `total_tokens` int(11) DEFAULT NULL,
  `reasoning_tokens` int(11) DEFAULT NULL,
  `is_hidden` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`course_id`),
  KEY `ix_course_review_summary_generated_at` (`generated_at`),
  KEY `ix_course_review_summary_is_hidden` (`is_hidden`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
