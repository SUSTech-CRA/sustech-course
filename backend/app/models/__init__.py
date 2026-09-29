from sqlalchemy.orm import declarative_base

Base = declarative_base()

from .user import (  # noqa: E402,F401
    Dept,
    DeptClass,
    Major,
    Student,
    Teacher,
    TeacherInfoHistory,
    ThirdPartySigninHistory,
    User,
    downvote_course,
    follow_course,
    follow_user,
    join_course,
    review_course,
    upvote_course,
)
from .review import (  # noqa: E402,F401
    Review,
    ReviewComment,
    ReviewCommentHistory,
    ReviewHistory,
    review_upvotes,
)
from .course import (  # noqa: E402,F401
    Course,
    CourseClass,
    CourseInfoHistory,
    CourseRate,
    CourseReviewSummary,
    CourseTerm,
    CourseTimeLocation,
    course_teachers,
)
from .notification import Notification  # noqa: E402,F401
from .image import ImageStore  # noqa: E402,F401
from .forum import ForumPost, ForumThread, forum_post_upvotes, forum_thread_upvotes  # noqa: E402,F401
from .note import Note, NoteComment, note_upvotes  # noqa: E402,F401
from .share import Share, ShareComment, share_upvotes  # noqa: E402,F401
from .utils import Announcement, Banner, RevokedToken, SearchLog  # noqa: E402,F401
