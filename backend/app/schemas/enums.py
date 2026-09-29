from enum import Enum


class CourseSortBy(str, Enum):
    RATE = "rate"
    RATE_ASC = "rate_asc"
    REVIEW_COUNT = "review_count"
    UPVOTE = "upvote"
    FOLLOW = "follow"
    JOIN = "join"
    NAME = "name"


class ReviewSortBy(str, Enum):
    UPVOTE = "upvote"
    # 按更新时间倒序（老版首页"最新点评"流）
    UPDATETIME_DESC = "updatetime_desc"
    # 按发布时间排序（老版课程页"最新点评/最旧点评"）
    PUBTIME_DESC = "pubtime_desc"
    PUBTIME = "pubtime"
    SCORE_DESC = "score_desc"
    SCORE = "score"


class SearchType(str, Enum):
    ALL = "all"
    COURSE = "course"
    REVIEW = "review"
    TEACHER = "teacher"


class ReviewFeedFilter(str, Enum):
    LATEST = "latest"
    FOLLOWING = "following"
    FOLLOWING_USERS = "following_users"
