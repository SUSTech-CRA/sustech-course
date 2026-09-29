from pydantic import BaseModel

from app.schemas.course import CourseBrief
from app.schemas.user import UserBrief


class DistributionPoint(BaseModel):
    label: str
    value: int


class SeriesPoint(BaseModel):
    label: str
    value: int
    cumulative: int | None = None


class SiteStatsResponse(BaseModel):
    user_count: int
    course_count: int
    review_count: int
    teacher_count: int
    registered_teacher_count: int = 0
    running_days: int = 0
    course_avg_rate: float | None = None
    course_avg_rate_count: float | None = None
    review_rate_distribution: list[DistributionPoint] = []
    course_rate_distribution: list[DistributionPoint] = []
    course_review_count_distribution: list[SeriesPoint] = []
    user_review_count_distribution: list[SeriesPoint] = []
    review_monthly_distribution: list[SeriesPoint] = []
    user_monthly_distribution: list[SeriesPoint] = []


class RankingsStats(BaseModel):
    avg_rate: float = 0
    avg_rate_count: float = 0
    avg_review_upvotes: float = 0
    avg_review_length: float = 0


class CourseRankingItem(CourseBrief):
    normalized_rate: float | None = None


class TeacherRankingItem(BaseModel):
    id: int
    name: str | None = None
    dept: str | None = None
    course_count: int = 0
    review_count: int = 0
    normalized_rate: float | None = None


class ReviewRankingItem(BaseModel):
    course_id: int
    course_name: str
    review_id: int
    author: UserBrief | None = None
    author_name: str = "匿名用户"
    is_anonymous: bool = False
    upvote_count: int = 0
    content_length: int | None = None


class UserRankingItem(BaseModel):
    user: UserBrief
    reviews_count: int = 0
    review_upvotes_count: int = 0
    review_length: int = 0
    score: float = 0


class RankingsResponse(BaseModel):
    stats: RankingsStats
    top_teachers: list[TeacherRankingItem] = []
    top_rated_courses: list[CourseRankingItem] = []
    popular_courses: list[CourseRankingItem] = []
    top_reviews: list[ReviewRankingItem] = []
    long_reviews: list[ReviewRankingItem] = []
    top_users: list[UserRankingItem] = []
