from flask import Blueprint,render_template,abort,redirect,url_for,request,abort,jsonify
from flask_login import login_required
from flask_babel import gettext as _
from app.models import *
from app import db
from app.utils import sanitize
from sqlalchemy import or_, func, sql
from datetime import datetime

stats = Blueprint('stats',__name__)


@stats.route('/')
def index():
    '''view site stats'''
    today = datetime.now().strftime("%Y/%m/%d")
    site_stat = dict()
    site_stat['user_count'] = User.query.count()
    site_stat['course_count'] = Course.query.count()
    site_stat['review_count'] = Review.query.count()
    site_stat['registered_teacher_count'] = User.query.filter(User.identity == 'Teacher').count()

    # find the distribution of the number of reviews per course
    course_review_counts = db.session.query(func.count(Review.id).label('review_count')).group_by(Review.course_id).subquery()
    course_review_count_dist = db.session.query(db.text('review_count'), func.count().label('course_count')).select_from(course_review_counts).group_by(db.text('review_count')).order_by(db.text('review_count')).all()

    # find the distribution of the number of reviews written by each user
    user_review_counts = db.session.query(func.count(Review.id).label('review_count')).group_by(Review.author_id).subquery()
    user_review_count_dist = db.session.query(db.text('review_count'), func.count().label('user_count')).select_from(user_review_counts).group_by(db.text('review_count')).order_by(db.text('review_count')).all()

    # find the distribution of publication dates of reviews (count per month)
    review_dates = db.session.query(func.year(Review.publish_time).label('publish_year'), func.month(Review.publish_time).label('publish_month'), func.count().label('review_count')).group_by(db.text('publish_year'), db.text('publish_month')).order_by(db.text('publish_year'), db.text('publish_month')).all()

    # find the distribution of registration dates of user (count per month)
    user_reg_dates = db.session.query(func.year(User.register_time).label('reg_year'), func.month(User.register_time).label('reg_month'), func.count().label('user_count')).group_by(db.text('reg_year'), db.text('reg_month')).order_by(db.text('reg_year'), db.text('reg_month')).all()

    # find the distribution of review rates
    review_rates = db.session.query(func.count(Review.id).label('count'), Review.rate).group_by(Review.rate).order_by(Review.rate).all()

    # find the distribution of course rates
    course_rates = db.session.query(func.floor(CourseRate._rate_average).label('rate'), func.count(func.floor(CourseRate._rate_average)).label('count')).filter(CourseRate._rate_average > 0).group_by(db.text('rate')).order_by(db.text('rate')).all()

    return render_template('site-stats.html', site_stat=site_stat, course_review_count_dist=course_review_count_dist, user_review_count_dist=user_review_count_dist, review_dates=review_dates, user_reg_dates=user_reg_dates, review_rates=review_rates, course_rates=course_rates, date=today)


@stats.route('/rankings/')
def view_ranking():
    '''view rankings'''
    today = datetime.now().strftime("%Y/%m/%d")

    topk_count = 30
    default_show_count = 10

    # helper queries for fetching top teachers
    # join Teacher, Course, Review, Dept classes via course_teachers intermediate table
    teacher_rank_join = sql.outerjoin(sql.join(Teacher, sql.join(course_teachers, sql.join(Course, Review, Course.id == Review.course_id), course_teachers.c.course_id == Course.id), course_teachers.c.teacher_id == Teacher.id), Dept, Dept.id == Course.dept_id)
    # find teachers with low rating courses (average rate < 8)
    teachers_with_low_rating_course = sql.select(Teacher.id).join(course_teachers).join(Course).join(CourseRate).filter(CourseRate._rate_average < 8)
    # find teachers with at least 3 high rating courses (average rate > 9)
    teacher_query_with_high_rating_course = sql.select(Teacher.id.label('teacher_id'), func.count(CourseRate.id).label('course_count')).select_from(sql.join(Teacher, sql.join(course_teachers, CourseRate, course_teachers.c.course_id == CourseRate.id), Teacher.id == course_teachers.c.teacher_id)).filter(CourseRate._rate_average > 9).group_by(Teacher.id)
    teachers_with_high_rating_course = db.session.query(db.text('teacher_id')).select_from(teacher_query_with_high_rating_course).filter(db.text('course_count >= 3')).all()
    # we have to get the teachers to Python instead of using SQL subquery due to a problem in sqlalchemy
    teachers_with_high_rating_course = [teacher[0] for teacher in teachers_with_high_rating_course]

    # helper subquery for finding average and total review rating of teachers because SQL does not allow ordering by aggregation fields
    teacher_rank_unordered = (db.session.query(Teacher.id.label('teacher_id'),
                                               Teacher.name.label('teacher_name'),
                                               Dept.name.label('dept_id'),
                                               func.count(func.distinct(Course.id)).label('course_count'),
                                               func.count(Review.id).label('review_count'),
                                               func.avg(Review.rate).label('avg_review_rate'),
                                               func.sum(Review.rate).label('total_review_rate'))
                              .select_from(teacher_rank_join)
                              .filter(Teacher.id.not_in(teachers_with_low_rating_course))
                              .filter(Teacher.id.in_(teachers_with_high_rating_course))
                              .group_by(Teacher.id)
                              .subquery())

    # find top 10 teachers with at least 3 high rating courses and does not have any low rating course
    # definition of high rating courses: average rate > 9
    # definition of low rating course: average rate < 8
    # order by: normalized rating: (total_rate + avg_rate * avg_rate_count) / (rate_count + avg_rate_count)
    #                              total_rate is the sum of rates to this teacher
    #                              avg_rate is the average rating across the entire site
    #                              avg_rate_count is the average number of ratings per course across the entire site
    #                              rate_count is the number of ratings to this teacher
    #           The normalized rating is equivalent to adding avg_rate_count number of reviews with avg_rate to each teacher.
    teacher_rank = (db.session.query(db.text('teacher_id'), db.text('teacher_name'), db.text('dept_id'), db.text('course_count'), db.text('review_count'), db.text('avg_review_rate'), db.text('total_review_rate'))
                              .select_from(teacher_rank_unordered)
                              .order_by(Course.generic_query_order(db.text('total_review_rate'), db.text('review_count')).desc())
                              .limit(topk_count).all())

    # find top 10 users who has written the most number of reviews
    avg_upvote_count_result = db.session.query(func.sum(Review.upvote_count) / func.count(Review.id)).first()
    avg_upvote_count = avg_upvote_count_result[0]
    user_rank = (db.session.query(User.id,
                                  User.username,
                                  func.count(Review.id).label('reviews_count'),
                                  func.sum(Review.upvote_count).label('review_upvotes_count'),
                                  (func.count(Review.id) + func.sum(Review.upvote_count) / avg_upvote_count).label('score'))
                           .join(User)
                           .group_by(Review.author_id)
                           .order_by(db.text('score desc'))
                           .limit(topk_count).all())

    # find top 10 reviews with the most number of upvotes
    review_rank_join = sql.join(User, sql.join(Course, Review, Course.id == Review.course_id), User.id == Review.author_id)
    review_rank = (db.session.query(Course.id.label('course_id'),
                                    Course.name.label('course_name'),
                                    Review.id.label('review_id'),
                                    User.id.label('author_id'),
                                    User.username.label('author_username'),
                                    Review.upvote_count.label('review_upvotes_count'))
                             .join(User).join(Course)
                             .filter(func.length(Review.content) >= 500)
                             .order_by(Review.upvote_count.desc())
                             .limit(topk_count).all())

    # find top 10 longest reviews
    review_length_rank = (db.session.query(Course.id.label('course_id'),
                                           Course.name.label('course_name'),
                                           Review.id.label('review_id'),
                                           User.id.label('author_id'),
                                           User.username.label('author_username'),
                                           Review.upvote_count.label('review_upvotes_count'),
                                           func.length(Review.content).label('review_length'))
                                    .join(User).join(Course)
                                    .order_by(func.length(Review.content).desc())
                                    .limit(topk_count).all())

    # find top 10 courses with at least 20 reviews and highest normalized average rating
    top_rated_courses = (Course.query.join(CourseRate)
                               .filter(CourseRate.review_count >= 20)
                               .order_by(Course.QUERY_ORDER())
                               .limit(topk_count).all())

    # find top 10 courses with at least 10 reviews and lowest normalized average rating
    worst_rated_courses = (Course.query.join(CourseRate)
                                 .filter(CourseRate.review_count >= 10)
                                 .order_by(Course.REVERSE_QUERY_ORDER())
                                 .limit(topk_count).all())

    # find top 10 courses with the highest number of reviews
    popular_courses = (Course.query.join(CourseRate)
                             .order_by(CourseRate.review_count.desc(), CourseRate._rate_average.desc())
                             .limit(topk_count).all())

    return render_template('ranking.html', default_show_count=default_show_count, teachers=teacher_rank, users=user_rank, reviews=review_rank, long_reviews=review_length_rank, top_rated_courses=top_rated_courses, worst_rated_courses=worst_rated_courses, popular_courses=popular_courses, date=today, this_module='stats.view_ranking')


def date_to_term(date):
    if date.month <= 1:
        year = date.year - 1
        term = 1
    elif date.month <= 6:
        year = date.year - 1
        term = 2
    elif date.month <= 8:
        year = date.year - 1
        term = 3
    else:
        year = date.year
        term = 1
    return str(year) + str(term)

def str_to_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y/%m/%d")
    except:
        try:
            return datetime.strptime(date_str, "%Y/%m/%d %H:%M:%S")
        except:
            try:
                return datetime.strptime(date_str, "%Y/%m/%d %H:%M")
            except:
                abort(400, "Invalid date format, accepted format: %Y/%m/%d")
                return None

@stats.route('/stats_history/')
def stats_history():
    '''view site stats history'''
    date_str = request.args.get('date')
    if not date_str:
        return index()
    date = str_to_date(date_str)

    site_stat = dict()
    site_stat['user_count'] = User.query.filter(User.register_time < date).count()
    site_stat['course_count'] = Course.query.distinct(Course.id).join(CourseTerm).filter(CourseTerm.term < date_to_term(date)).count()
    site_stat['review_count'] = Review.query.filter(Review.publish_time < date).count()
    site_stat['registered_teacher_count'] = User.query.filter(User.identity == 'Teacher').filter(User.register_time < date).count()

    # find the distribution of the number of reviews per course
    course_review_counts = db.session.query(func.count(Review.id).label('review_count')).filter(Review.publish_time < date).group_by(Review.course_id).subquery()
    course_review_count_dist = db.session.query(db.text('review_count'), func.count().label('course_count')).select_from(course_review_counts).group_by(db.text('review_count')).order_by(db.text('review_count')).all()

    # find the distribution of the number of reviews written by each user
    user_review_counts = db.session.query(func.count(Review.id).label('review_count')).filter(Review.publish_time < date).group_by(Review.author_id).subquery()
    user_review_count_dist = db.session.query(db.text('review_count'), func.count().label('user_count')).select_from(user_review_counts).group_by(db.text('review_count')).order_by(db.text('review_count')).all()

    # find the distribution of publication dates of reviews (count per month)
    review_dates = db.session.query(func.year(Review.publish_time).label('publish_year'), func.month(Review.publish_time).label('publish_month'), func.count().label('review_count')).group_by(db.text('publish_year'), db.text('publish_month')).filter(Review.publish_time < date).order_by(db.text('publish_year'), db.text('publish_month')).all()

    # find the distribution of registration dates of user (count per month)
    user_reg_dates = db.session.query(func.year(User.register_time).label('reg_year'), func.month(User.register_time).label('reg_month'), func.count().label('user_count')).group_by(db.text('reg_year'), db.text('reg_month')).filter(User.register_time < date).order_by(db.text('reg_year'), db.text('reg_month')).all()

    # find the distribution of review rates
    review_rates = db.session.query(func.count(Review.id).label('count'), Review.rate).filter(Review.publish_time < date).group_by(Review.rate).order_by(Review.rate).all()

    # find the distribution of course rates
    course_rate_subquery = db.session.query(func.floor(func.avg(Review.rate)).label('rate')).filter(Review.publish_time < date).group_by(Review.course_id)
    course_rates = db.session.query(db.text('rate'), func.count(db.text('rate')).label('count')).select_from(course_rate_subquery).group_by(db.text('rate')).order_by(db.text('rate')).all()

    return render_template('site-stats.html', site_stat=site_stat, course_review_count_dist=course_review_count_dist, user_review_count_dist=user_review_count_dist, review_dates=review_dates, user_reg_dates=user_reg_dates, review_rates=review_rates, course_rates=course_rates, date=date_str)
