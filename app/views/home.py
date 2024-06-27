from flask import Blueprint, request, redirect, url_for, render_template, flash, abort, jsonify, make_response, session, current_app
from flask_login import login_user, login_required, current_user, logout_user
from app.models import User, RevokedToken as RT, Course, CourseRate, CourseTerm, Teacher, Review, Notification, follow_course, follow_user, SearchLog, ThirdPartySigninHistory, Announcement
from app.forms import LoginForm, RegisterForm, ForgotPasswordForm, ResetPasswordForm
from app.utils import ts, send_confirm_mail, send_reset_password_mail
from flask_babel import gettext as _
from datetime import datetime
from sqlalchemy import union, or_
from sqlalchemy.sql.expression import literal_column, text
from app import db
from app import app
from .course import deptlist
import re
import requests
from oauthlib import oauth2
import uuid
import faker
from cachelib import SimpleCache
import time

home = Blueprint('home',__name__)
OAUTH = app.config['OAUTH']
fake = faker.Faker()

def gen_index_url():
    if 'DEBUG' in app.config and app.config['DEBUG']:
        return url_for('home.index', _external=True)
    else:
        return url_for('home.index', _external=True, _scheme='https')

def redirect_to_index():
    return redirect(gen_index_url())

@home.route('/')
def index():
    return latest_reviews()

def gen_reviews_query():
    reviews = Review.query.filter(Review.is_blocked == False).filter(Review.is_hidden == False)
    if current_user.is_authenticated and current_user.identity == 'Student':
        return reviews
    elif current_user.is_authenticated:
        return reviews.filter(or_(Review.only_visible_to_student == False, Review.author == current_user))
    else:
        return reviews.filter(Review.only_visible_to_student == False)

def gen_ordered_reviews_query():
    return gen_reviews_query().order_by(Review.update_time.desc())

@home.route('/latest_reviews')
def latest_reviews():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    reviews_paged = gen_ordered_reviews_query().paginate(page=page, per_page=per_page)
    return render_template('latest-reviews.html', reviews=reviews_paged, title='全站最新点评', this_module='home.latest_reviews', hide_title=True)

@home.route('/feed.xml')
def latest_reviews_rss():
    reviews_paged = gen_ordered_reviews_query().paginate(page=1, per_page=100)
    rss_content = render_template('feed.xml', reviews=reviews_paged)
    response = make_response(rss_content)
    response.headers['Content-Type'] = 'application/rss+xml; charset=utf-8'
    return response

sitemap_cache = SimpleCache()
@app.route('/sitemap.xml')
def latest_reviews_sitemap():
    # 尝试从缓存中获取数据
    response = sitemap_cache.get('latest_reviews_sitemap')
    if response is None:
        reviews_paged = gen_ordered_reviews_query().paginate(page=1, per_page=1000)
        rss_content = render_template('sitemap.xml', reviews=reviews_paged)
        response = make_response(rss_content)
        response.headers['Content-Type'] = 'application/xml; charset=utf-8'
        # 缓存数据和响应
        sitemap_cache.set('latest_reviews_sitemap', response, timeout=60*60)  # 缓存一小时
    return response

@home.route('/follow_reviews')
def follow_reviews():
    if not current_user.is_authenticated:
        return redirect(url_for('home.latest_reviews', _external=True, _scheme='https'))
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    follow_type = request.args.get('follow_type', 'course', type=str)

    if follow_type == 'user':
        # show reviews for followed users
        reviews = gen_reviews_query().filter(Review.is_anonymous == False).join(follow_user, Review.author_id == follow_user.c.followed_id).filter(follow_user.c.follower_id == current_user.id)
        title = '「我关注的人」最新点评'
    else:
        # show reviews for followed courses
        reviews = gen_reviews_query().join(follow_course, Review.course_id == follow_course.c.course_id).filter(follow_course.c.user_id == current_user.id)
        title = '「我关注的课程」最新点评'

    reviews_to_show = reviews.filter(Review.author_id != current_user.id).order_by(Review.update_time.desc())
    reviews_paged = reviews_to_show.paginate(page=page, per_page=per_page)

    return render_template('latest-reviews.html', reviews=reviews_paged, follow_type=follow_type, title=title, this_module='home.follow_reviews')

@home.route('/signin/',methods=['POST','GET'])
def signin():
    next_url = request.args.get('next') or gen_index_url()
    if current_user.is_authenticated:
        return redirect(next_url)
    form = LoginForm()
    error = ''
    if form.validate_on_submit():
        user, status, confirmed = User.authenticate(form['username'].data,form['password'].data)
        remember = form['remember'].data
        if user and not user.is_deleted:
            if status and confirmed:
                #validate uesr
                login_user(user, remember=remember)
                if request.args.get('ajax'):
                    return jsonify(status=200, next=next_url)
                else:
                    return redirect(next_url)
            elif status:
                '''没有确认邮箱的用户'''
                message = '请点击邮箱里的激活链接。 <a href=%s>重发激活邮件</a>' % url_for('.confirm_email',
                    email=user.email,
                    action='send',
                    _external=True,
                    _scheme='https')
                if request.args.get('ajax'):
                    return jsonify(status=403, msg=message)
                else:
                    return render_template('feedback.html', status=False, message=message)
            else:
                error = _('用户名或密码错误！')
        else:
            error = _('用户名或密码错误！')
    elif request.method == 'POST':
        error = '表单验证错误：' + str(form.errors)

    #TODO: log the form errors
    if request.args.get('ajax'):
        return jsonify(status=404, msg=error)
    else:
        return render_template('signin.html',form=form, error=error, title='登录')

@home.route("/login/oauth/", methods=["GET"])
def oauth():
    """ 当用户点击该链接时，把用户重定向到OAuth2登录页面。 """
    client = oauth2.WebApplicationClient(OAUTH["client_id"])
    state = client.state_generator()    # 生成随机的state参数，用于防止CSRF攻击
    auth_url = client.prepare_request_uri(OAUTH["auth_url"],
                                          OAUTH["redirect_uri"],
                                          OAUTH["scope"],
                                          state)  # 构造完整的auth_url，接下来要让用户重定向到它
    session["oauth_state"] = state
    return redirect(auth_url)


@home.route("/login/oauth/callback/", methods=["GET"])
def oauth_callback():
    """ 用户在同意授权之后，会被重定向回到这个URL。 """
    # 解析得到code
    client = oauth2.WebApplicationClient(OAUTH["client_id"])
    code = client.parse_request_uri_response(request.url, session["oauth_state"]).get("code")

    # 获取token
    d = {
        'grant_type' : 'authorization_code',
        'client_id' : OAUTH["client_id"],
        'client_secret' :OAUTH["client_secret"],
        'code': code,
        'redirect_uri': OAUTH["redirect_uri"],
    }
    r = requests.post(OAUTH["token_url"], data=d)
    access_token = r.json().get("access_token")

    # 查询用户名并储存
    headers = {'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': f'Bearer {access_token}'
    }
    r = requests.get(OAUTH["api_url"], headers=headers)
    data = r.json()
    session["preferred_username"] =  fake.name()
    session["given_name"] = data.get("given_name")
    session["family_name"] = data.get("family_name")
    session["full_name"] = data.get("name")
    session["email"] = data.get("email")
    email = session["email"]
    session["access_token"] = access_token  # 以后存到用户表中
    # print(User.query.filter_by(email=session["email"]).first())

    #检查用户是否已经注册
    if (not User.query.filter_by(email=session["email"]).first()): #没注册会进入if逻辑
        username = fake.name().replace(" ", "_")
        user = User(username=username, email=email, password=str(uuid.uuid4().hex)) # random password
        email_suffix = email.split('@')[-1]
        if email_suffix == 'mail.sustech.edu.cn':
            user.identity = 'Student'
        elif email_suffix == 'sustech.edu.cn':
            user.identity = 'Teacher'
        user.save()
        user.confirm()
        login_user(user)
    else:
        # print("found existed user!")
        user = User.query.filter_by(email=email).first_or_404()
        login_user(user)  # 根据邮箱登录用户
    return redirect_to_index()


# 3rdparty signin should have url format: https://${icourse_site_url}/signin-3rdparty/?from_app=${from_app}&next_url=${next_url}&challenge=${challenge}
# here, ${from_app} is the 3rdparty site name displayed to the user
# here, ${next_url} is the 3rdparty login verification URL to the 3rdparty site
# here, ${challenge} is a challenge string provided by the 3rdparty site
@home.route('/signin-3rdparty/', methods=['GET'])
def signin_3rdparty():
    from_app = request.args.get('from_app')
    if not from_app:
        abort(400, description="from_app parameter not specified")
    next_url = request.args.get('next_url')
    if not next_url:
        abort(400, description="next_url parameter not specified")
    challenge = request.args.get('challenge')
    if not challenge:
        abort(400, description="challenge parameter not specified")
    return render_template('signin-3rdparty.html', from_app=from_app, next_url=next_url, current_user=current_user, challenge=challenge, title='第三方登录')


def update_3rdparty_signin_history_to_verified(email, token):
    history = ThirdPartySigninHistory.query.filter_by(email=email, token=token).first()
    history.verify_time = datetime.utcnow()
    history.add()


@home.route('/verify-3rdparty-signin/', methods=['GET'])
def verify_3rdparty_signin():
    email = request.args.get('email')
    if not email:
        abort(400, description="email parameter not specified")
    token = request.args.get('token')
    if not token:
        abort(400, description="token parameter not specified")

    user = User.query.filter_by(email=email).first()
    if not user:
        abort(403, description="user does not exist or token is invalid")
    if user.token_3rdparty == token:
        user.token_3rdparty = None
        user.save()
        update_3rdparty_signin_history_to_verified(email, token)
        resp = jsonify(success=True)
        return resp
    else:
        abort(403, description="user does not exist or token is invalid")


@home.route('/signup/',methods=['GET','POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(request.args.get('next') or gen_index_url())
    form = RegisterForm()
    if form.validate_on_submit():
        # google
        # recaptcha_response = request.form.get('g-recaptcha-response')
        # recaptcha_challenge_data = {
        #     'secret': app.config['RECAPTCHA_SECRET_KEY'],
        #     'response': recaptcha_response
        # }
        # recaptcha_challenge_response = requests.post('https://recaptcha.google.cn/recaptcha/api/siteverify', data=recaptcha_challenge_data)

        # cloudflare
        recaptcha_response = request.form.get('cf-turnstile-response')
        recaptcha_challenge_data = {
            'secret': app.config['RECAPTCHA_SECRET_KEY'],
            'response': recaptcha_response
        }
        recaptcha_challenge_response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data=recaptcha_challenge_data)

        recaptcha_challenge_result = recaptcha_challenge_response.json()
        if recaptcha_challenge_result['success']:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

            # 检查用户名是否已被注册
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('该用户名已被注册，请选择其他用户名。')
                return render_template('signup.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'], title='注册')

            # 检查邮箱是否已被注册
            existing_email = User.query.filter_by(email=email).first()
            if existing_email:
                flash('该邮箱已被注册，请使用其他邮箱。')
                return render_template('signup.html', form=form, recaptcha_site_key=app.config['RECAPTCHA_SITE_KEY'], title='注册')

            user = User(username=username, email=email, password=password)
            email_suffix = email.split('@')[-1]
            email_prefix = email.split('@')[0]
            # if prefix does not contain "list-"
            if email_prefix.find("list-") == -1:
                if email_suffix == 'mail.sustech.edu.cn':
                    user.identity = 'Student'
                elif email_suffix == 'sustech.edu.cn':
                    user.identity = 'Teacher'
                ok,message = user.bind_teacher(email)
                #TODO: deal with bind feedback
            else:
                abort(403, "必须使用科大学生或教师邮箱注册")
            send_confirm_mail(user.email)
            user.save()
            #login_user(user)
            '''注册完毕后显示一个需要激活的页面'''
            return render_template('feedback.html', status=True, message=_('我们已经向您发送了激活邮件，请在邮箱中点击激活链接。如果您没有收到邮件，有可能是在垃圾箱中。'), title='注册')
        else:
            return render_template('feedback.html', status=False, message=_('验证码错误，请重试。'), title='注册')
#TODO: log error
    if form.errors:
        # {'username': ['此用户名已被他人使用！'], 'email': ['此邮件地址已被注册！']}
        print(form.errors)
        flash(form.errors, 'error')
    return render_template('signup.html', form=form, recaptcha_site_key = app.config['RECAPTCHA_SITE_KEY'], title='注册')


@home.route('/confirm-email/')
def confirm_email():
    if current_user.is_authenticated:
        #logout_user()
        return redirect(request.args.get('next') or gen_index_url())
    action = request.args.get('action')
    if action == 'confirm':
        token = request.args.get('token')
        if not token:
            return render_template('feedback.html', status=False, message=_('此激活链接无效，请准确复制邮件中的链接。'))
        if RT.query.get(token):
            return render_template('feedback.html', status=False, message=_('此激活链接已被使用过。'))
        RT.add(token)
        email = None
        try:
            email = ts.loads(token, salt=app.config['EMAIL_CONFIRM_SECRET_KEY'], max_age=86400)
        except:
            abort(404)

        user = User.query.filter_by(email=email).first_or_404()
        user.confirm()
        flash(_('Your email has been confirmed'))
        login_user(user)
        return redirect_to_index()
    elif action == 'send':
        email = request.args.get('email')
        user = User.query.filter_by(email=email).first_or_404()
        if not user.confirmed:
            send_confirm_mail(email)
        return render_template('feedback.html', status=True, message=_('邮件已经发送，请查收！'), title='发送验证邮件')
    else:
        abort(404)


@home.route('/logout/')
@login_required
def logout():
    logout_user()
    return redirect_to_index()

@home.route('/change-password/', methods=['GET'])
def change_password():
    '''在控制面板里发邮件修改密码，另一个修改密码在user.py里面'''
    if not current_user.is_authenticated:
        return redirect(url_for('home.signin', _external=True, _scheme='https'))
    send_reset_password_mail(current_user.email)
    return render_template('feedback.html', status=True, message=_('密码重置邮件已经发送。'), title='修改密码')


@home.route('/reset-password/', methods=['GET','POST'])
def forgot_password():
    ''' 忘记密码'''
    if current_user.is_authenticated:
        return redirect(request.args.get('next') or gen_index_url())
    form = ForgotPasswordForm()
    if form.validate_on_submit():

        # google recaptcha
        # recaptcha_response = request.form.get('g-recaptcha-response')
        # recaptcha_challenge_data = {
        #     'secret': app.config['RECAPTCHA_SECRET_KEY'],
        #     'response': recaptcha_response
        # }
        # recaptcha_challenge_response = requests.post('https://recaptcha.google.cn/recaptcha/api/siteverify', data=recaptcha_challenge_data)

        # cloudflare
        recaptcha_response = request.form.get('cf-turnstile-response')
        recaptcha_challenge_data = {
            'secret': app.config['RECAPTCHA_SECRET_KEY'],
            'response': recaptcha_response
        }
        recaptcha_challenge_response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify',
                                                     data=recaptcha_challenge_data)

        recaptcha_challenge_result = recaptcha_challenge_response.json()

        if recaptcha_challenge_result['success']:
            email = form['email'].data
            user = User.query.filter_by(email=email).first()
            if user:
                send_reset_password_mail(email)
                message = _('密码重置邮件已发送。')  #一个反馈信息
                status = True
            else:
                message = _('此邮件地址尚未被注册。')
                status = False
            return render_template('feedback.html', status=status, message=message)
        else:
            return render_template('feedback.html', status=False, message=_('验证码错误，请勿重复提交表单，<a href="/reset-password/">点此返回密码重置页面</a>'), title='忘记密码')
    return render_template('forgot-password.html', recaptcha_site_key = app.config['RECAPTCHA_SITE_KEY'], title='忘记密码')

@home.route('/reset-password/<string:token>/', methods=['GET','POST'])
def reset_password(token):
    '''重设密码'''
    if RT.query.get(token):
        return render_template('feedback.html', status=False, message=_('此密码重置链接已被使用过。'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        RT.add(token)
        try:
            email = ts.loads(token, salt=app.config['PASSWORD_RESET_SECRET_KEY'], max_age=86400)
        except:
            return render_template('feedback.html', status=False, message=_('此密码重置链接无效，请准确复制邮件中的链接。'))
        user = User.query.filter_by(email=email).first_or_404()
        password = form['password'].data
        user.set_password(password)
        logout_user()
        flash('密码已经修改，请使用新密码登录。')
        return redirect(url_for('home.signin', _external=True, _scheme='https'))
    return render_template('reset-password.html', form=form, title='重设密码')


class MyPagination(object):

    def __init__(self, page, per_page, total, items):
        self.page = page
        self.per_page = per_page
        self.total = total
        self.items = items

    @property
    def pages(self):
        return int((self.total + self.per_page - 1) / self.per_page)

    @property
    def has_prev(self):
        return self.page > 1

    @property
    def has_next(self):
        return self.page < self.pages

    def iter_pages(self, left_edge=2, left_current=2,
                   right_current=5, right_edge=2):
        last = 0
        for num in range(1, self.pages + 1):
            if num <= left_edge or \
               (num > self.page - left_current - 1 and \
                num < self.page + right_current) or \
               num > self.pages - right_edge:
                if last + 1 != num:
                    yield None
                yield num
                last = num


@home.route('/search-reviews/')
def search_reviews():
    ''' 搜索点评内容 '''
    start_time = time.time()
    query_str = request.args.get('q')
    if not query_str:
        return redirect_to_index()

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    keywords = re.sub(r'''[~`!@#$%^&*{}[]|\\:";'<>?,./]''', ' ', query_str).split()
    if not keywords:
        return render_template('search-reviews.html', keyword=query_str,
                               reviews=MyPagination(page=0, per_page=0, total=0, items=[]),
                               title="无效的搜索关键词")
    max_keywords_allowed = 10
    if len(keywords) > max_keywords_allowed:
        keywords = keywords[:max_keywords_allowed]

    unioned_query = None
    for keyword in keywords:
        content_query = Review.query.filter(Review.content.like('%' + keyword + '%'))
        if unioned_query is None:
            unioned_query = content_query
        else:
            unioned_query = unioned_query.union(content_query)

        author_query = Review.query.join(Review.author).filter(User.username == keyword).filter(Review.is_anonymous == False).filter(User.is_profile_hidden == False)
        course_query = Review.query.join(Review.course).filter(Course.name.like('%' + keyword + '%'))
        courseries_query = Review.query.join(Review.course).join(CourseTerm).filter(CourseTerm.courseries.like(keyword + '%')).filter(CourseTerm.course_id == Course.id)
        teacher_query = Review.query.join(Review.course).join(Course.teachers).filter(Teacher.name == keyword)
        unioned_query = unioned_query.union(author_query).union(course_query).union(courseries_query).union(teacher_query)

    unioned_query = unioned_query.filter(Review.is_blocked == False).filter(Review.is_hidden == False)
    if not current_user.is_authenticated or current_user.identity != 'Student':
        if current_user.is_authenticated:
            unioned_query = unioned_query.filter(or_(Review.only_visible_to_student == False, Review.author == current_user))
        else:
            unioned_query = unioned_query.filter(Review.only_visible_to_student == False)
    reviews_paged = unioned_query.order_by(Review.update_time.desc()).paginate(page=page, per_page=per_page)

    if reviews_paged.total > 0:
        title = '搜索点评「' + query_str + '」'
    else:
        title = '您的搜索「' + query_str + '」没有匹配到任何点评'

    search_log = SearchLog()
    search_log.keyword = query_str
    if current_user.is_authenticated:
        search_log.user_id = current_user.id
    search_log.module = 'search_reviews'
    search_log.page = page
    search_log.save()
    print(f"search_reviews: {time.time() - start_time} seconds")

    return render_template('search-reviews.html', reviews=reviews_paged,
                title=title,
                this_module='home.search_reviews', keyword=query_str)

@home.route('/search-reviews-meilisearch/')
def search_reviews_meilisearch():
    ''' meilisearch搜索点评内容 '''
    start_time = time.time()
    # 用户可控制的参数
    query = request.args.get('q', '')  # 默认为空字符串
    page = request.args.get('page', 1,  type=int)  # 默认为第一页
    per_page = request.args.get('per_page', 10, type=int)

    # keywords = re.sub(r'''[~`!@#$%^&*{}[]|\\:";'<>?,./]''', ' ', query).split()
    # if not keywords:
    #     return render_template('search-reviews.html', keyword=query,
    #                            reviews=MyPagination(page=0, per_page=0, total=0, items=[]),
    #                            title="无效的搜索关键词")
    # # add quotes to each keyword, and join them with space
    # query_with_quotes = ' '.join([f'"{keyword}"' for keyword in keywords])


    # 构建搜索请求
    search_params = {
        "q": query,
        "limit": 100,
        "page": 1,
        "hitsPerPage": 100,
        "attributesToSearchOn": ["content"]
    }

    meilisearch_api_key = app.config['MEILISEARCH_KEY']
    headers = {
        "Authorization": f"Bearer {meilisearch_api_key}",
        "Content-Type": "application/json"
    }

    # 向MeiliSearch发送请求
    response = requests.post('http://127.0.0.1:7700/indexes/reviews_mysql/search', json=search_params, headers=headers)

    query_result_json = response.json()

    # extract id of review from response
    review_ids = [hit['id'] for hit in query_result_json['hits']]
    # print(f"search_reviews_meilisearch get id: {time.time() - start_time} seconds")
    from sqlalchemy.sql.expression import case

    # 确保 review_ids 不为空
    if review_ids:
        # 构建一个 case 语句用于排序
        order_by_case = case(
            {id: index for index, id in enumerate(review_ids)},
            value=Review.id
        )

        reviews = Review.query.filter(Review.id.in_(review_ids)) \
            .order_by(order_by_case)

        # 其余的筛选条件
        if not current_user.is_authenticated or current_user.identity != 'Student':
            if current_user.is_authenticated:
                reviews = reviews.filter(or_(Review.only_visible_to_student == False, Review.author == current_user))
            else:
                reviews = reviews.filter(Review.only_visible_to_student == False)

        # 应用分页
        reviews_paged = reviews.paginate(page=page, per_page=per_page)
    else:
        # 处理 review_ids 为空的情况
        reviews_paged = MyPagination(page=0, per_page=0, total=0, items=[])

    if reviews_paged.total > 0:
        title = '搜索点评「' + query + '」'
    else:
        title = '您的搜索「' + query + '」没有匹配到任何点评'

    search_log = SearchLog()
    search_log.keyword = query
    if current_user.is_authenticated:
        search_log.user_id = current_user.id
    search_log.module = 'search_reviews'
    search_log.page = page
    search_log.save()
    # print(f"search_reviews_meilisearch complete: {time.time() - start_time} seconds")

    return render_template('search-reviews.html', reviews=reviews_paged,
                title=title,
                this_module='home.search_reviews_meilisearch', keyword=query)

@home.route('/search-reviews-meilisearch-api/')
def search_reviews_meilisearch_api():
    ''' meilisearch搜索点评内容，纯前端模式（返回点评内容json） '''
    start_time = time.time()
    # 用户可控制的参数
    query = request.args.get('q', '')  # 默认为空字符串
    page = request.args.get('page', 1,  type=int)  # 默认为第一页
    per_page = request.args.get('per_page', 10, type=int)

    # 构建搜索请求
    search_params = {
          "q": query,
          "limit": per_page,
          "page": page,
          "hitsPerPage": per_page,
          "highlightPreTag": "<span class = \"search-result-highlight\" style=\"color:#B22222;font-weight:bold;\">",
          "highlightPostTag": "</span>",
        "attributesToHighlight": [
            "content"
        ],
        "attributesToSearchOn": [
            "content"
        ],
        "attributesToRetrieve": [
            "id",
            "content",
            "update_time",
            "author_id",
            "course_id",
            "is_anonymous",
            "only_visible_to_student",
            "is_hidden",
            "is_blocked"
        ]
    }

    meilisearch_api_key = app.config['MEILISEARCH_KEY']
    headers = {
        "Authorization": f"Bearer {meilisearch_api_key}",
        "Content-Type": "application/json"
    }

    # 向MeiliSearch发送请求
    response = requests.post('http://127.0.0.1:7700/indexes/reviews_mysql/search', json=search_params, headers=headers)

    query_result_json = response.json()

    # extract id of review from response
    review_ids = [hit['id'] for hit in query_result_json['hits']]
    # print(f"search_reviews_meilisearch get id: {time.time() - start_time} seconds")
    reviews = Review.query.filter(Review.id.in_(review_ids)).order_by(Review.update_time.desc())

    # use id to query the name & teacher of the course
    for review_id in review_ids:
        review = Review.query.get(review_id)
        # append course name & teacher name to the list
        query_result_json['hits'][review_ids.index(review_id)]['course_name'] = review.course.name
        # may have multiple teachers
        query_result_json['hits'][review_ids.index(review_id)]['teacher_name'] = '、'.join([teacher.name for teacher in review.course.teachers])
        # append author_name to the list, use author_id to query User table
        if not query_result_json['hits'][review_ids.index(review_id)]['is_anonymous']:
            query_result_json['hits'][review_ids.index(review_id)]['author_name'] = User.query.get(review.author_id).username
        else:
            query_result_json['hits'][review_ids.index(review_id)]['author_name'] = '匿名用户'
            query_result_json['hits'][review_ids.index(review_id)]['author_id'] = '-1'

    # user auth state
    user_authed = current_user.is_authenticated
    user_student = current_user.identity == 'Student' if user_authed else False
    # check if the review is visible to the user, if not delete it from the list
    # Filter the hits based on user authentication and role
    filtered_hits = [
        hit for hit in query_result_json['hits']
        if not (
                (hit.get('only_visible_to_student') and not user_student) or
                hit.get('is_hidden') or
                hit.get('is_blocked')
        )
    ]

    # Clean up each hit in the filtered list
    for hit in filtered_hits:
        for key in ['is_anonymous', 'only_visible_to_student', 'is_hidden', 'is_blocked']:
            hit.pop(key, None)  # Use pop to safely remove the key, None ensures no error if key is missing
            hit['_formatted'].pop(key, None)
            # also pop author_id from _formatted
            hit['_formatted'].pop('author_id', None)

    # Now, update the original hits list
    query_result_json['hits'] = filtered_hits


    return jsonify(query_result_json)

@home.route('/search-reviews-meilisearch-api-html/')
def search_reviews_meilisearch_api_html():
    ''' 渲染html用的，参数都用js处理 '''
    return render_template('search-reviews-meilisearch-api.html',this_module='home.search_reviews_meilisearch_api_html')

@home.route('/search-meilisearch-api/')
def search_meilisearch_api():
    ''' meilisearch聚合搜索（可以搜课名，老师，评论），纯前端模式（返回点评内容json） '''
    start_time = time.time()
    # 用户可控制的参数
    query = request.args.get('q', '')  # 默认为空字符串
    page = request.args.get('page', 1,  type=int)  # 默认为第一页
    per_page = request.args.get('per_page', 10, type=int)

    # 构建搜索请求
    search_params = {
          "queries": [
            {
              "indexUid": "courses_mysql",
              "q": query,
              "attributesToSearchOn": [
                "name",
                "course_code"
              ],
              "highlightPreTag": "<span class=\"highlight\">",
              "highlightPostTag": "</span>",
              "attributesToHighlight": [
                "name",
                "course_code"
              ],
              "limit": 100
            },
            {
              "indexUid": "teachers_mysql",
              "q": query,
              "attributesToSearchOn": [
                "name",
                "email"
              ],
              "highlightPreTag": "<span class=\"highlight\">",
              "highlightPostTag": "</span>",
              "attributesToHighlight": [
                "name"
              ],
              "limit": 100
            },
            {
              "indexUid": "reviews_mysql",
              "q": query,
              "attributesToSearchOn": [
                "content"
              ],
              "highlightPreTag": "<span class=\"highlight\">",
              "highlightPostTag": "</span>",
              "attributesToHighlight": [
                "content"
              ],
              "limit": 20
            }
          ]
        }

    meilisearch_api_key = app.config['MEILISEARCH_KEY']
    headers = {
        "Authorization": f"Bearer {meilisearch_api_key}",
        "Content-Type": "application/json"
    }

    # 向MeiliSearch发送请求
    response = requests.post('http://127.0.0.1:7700/multi-search', json=search_params, headers=headers)

    query_result_json = response.json()
    course_hit_json = query_result_json['results'][0]
    teacher_hit_json = query_result_json['results'][1]
    review_hit_json = query_result_json['results'][2]

    # print time
    print(f"search_meilisearch_api get id: {time.time() - start_time} seconds")
    start_time = time.time()

    # extract course id from response
    course_ids = [hit['id'] for hit in course_hit_json['hits']]
    # find courserate for each course
    for course_id in course_ids:
        # create a new json object to store course rate
        course = Course.query.get(course_id)
        # append course rate to the list
        rate = course._course_rate
        query_result_json['results'][0]['hits'][course_ids.index(course_id)]['course_rate_score'] = rate._rate_average
        query_result_json['results'][0]['hits'][course_ids.index(course_id)]['course_rate_total'] = rate._rate_total
        query_result_json['results'][0]['hits'][course_ids.index(course_id)]['course_rate_difficulty'] = rate._difficulty_total
        query_result_json['results'][0]['hits'][course_ids.index(course_id)]['course_rate_homework'] = rate._homework_total
        query_result_json['results'][0]['hits'][course_ids.index(course_id)]['course_rate_gain'] = rate._gain_total

        # in each query_result_json['results'][0]['hits'][course_ids.index(course_id)], only preserve id name course_code

    # extract id of review from response
    review_ids = [hit['id'] for hit in review_hit_json['hits']]
    # use id to query the name & teacher of the course
    for review_id in review_ids:
        review = Review.query.get(review_id)
        # append course name & teacher name to the list
        query_result_json['results'][2]['hits'][review_ids.index(review_id)]['course_name'] = review.course.name
        # may have multiple teachers
        query_result_json['results'][2]['hits'][review_ids.index(review_id)]['teacher_name'] = '、'.join([teacher.name for teacher in review.course.teachers])

    print(f"search_reviews_meilisearch done search: {time.time() - start_time} seconds")
    return jsonify(query_result_json)

@home.route('/search-google-cse/')
def search_google_cse():
    return render_template('search-google-cse.html',this_module='home.search_google_cse')


@home.route('/search/')
def search():
    ''' 搜索 '''
    start_time = time.time()
    query_str = request.args.get('q')
    if not query_str:
        return redirect_to_index()
    noredirect = request.args.get('noredirect')

    course_type = request.args.get('type',None,type=int)
    department = request.args.get('dept',None,type=int)
    campus = request.args.get('campus',None,type=str)
    #course_query = Course.query
    #if course_type:
    #    # 课程类型
    #    course_query = course_query.filter(Course.course_type==course_type)
    #if department:
    #    # 开课院系
    #    course_query = course_query.filter(Course.dept_id==department)
    #if campus:
    #    # 开课地点
    #    course_query = course_query.filter(Course.campus==campus)

    keywords = re.sub(r'''[~`!@#$%^&*{}[]|\\:";'<>?,./]''', ' ', query_str).split()
    if not keywords:
        return render_template('search.html', keyword=query_str,
                               courses=MyPagination(page=0, per_page=0, total=0, items=[]),
                               title="无效的搜索关键词")
    max_keywords_allowed = 10
    if len(keywords) > max_keywords_allowed:
        keywords = keywords[:max_keywords_allowed]

    def course_query_with_meta(meta):
        return db.session.query(Course, literal_column(str(meta)).label("_meta"))

    def teacher_match(q, keyword):
        return q.join(Course.teachers).filter(Teacher.name.like('%' + keyword + '%'))

    def exact_match(q, keyword):
        return q.filter(Course.name == keyword)

    def include_match(q, keyword):
        fuzzy_keyword = keyword.replace('%', '')
        return q.filter(Course.name.like('%' + fuzzy_keyword + '%'))

    def include_match_code(q, keyword):
        return q.filter(Course.course_code.like(keyword + '%'))

    def fuzzy_match(q, keyword):
        fuzzy_keyword = keyword.replace('%', '')
        return q.filter(Course.name.like('%' + '%'.join([ char for char in fuzzy_keyword ]) + '%'))

    def courseries_match(q, keyword):
        courseries_keyword = keyword.replace('%', '')
        return q.filter(CourseTerm.courseries.like(keyword + '%')).filter(CourseTerm.course_id == Course.id)

    def teacher_and_course_match_0(q, keywords):
        return fuzzy_match(teacher_match(q, keywords[0]), keywords[1])

    def teacher_and_course_match_1(q, keywords):
        return fuzzy_match(teacher_match(q, keywords[1]), keywords[0])

    def ordering(query_obj, keywords):
        # This function is very ugly because sqlalchemy generates anon field names for the literal meta field according to the number of union entries.
        # So, queries with different number of keywords have different ordering field names.
        # Expect to refactor this code.
        if len(keywords) == 1:
            ordering_field = 'anon_2_anon_3_anon_4_anon_5_'
        else:
            ordering_field = 'anon_2_anon_3_anon_4_'
        if len(keywords) >= 3:
            for count in range(5, len(keywords) + 3):
                ordering_field += 'anon_' + str(count) + '_'
        ordering_field += '_meta'
        return query_obj.join(CourseRate).order_by(text(ordering_field), Course.QUERY_ORDER())

    union_keywords = None
    if len(keywords) >= 2:
        union_keywords = (teacher_and_course_match_0(course_query_with_meta(0), keywords)
                          .union(teacher_and_course_match_1(course_query_with_meta(0), keywords)))

    for keyword in keywords:
        union_courses = (teacher_match(course_query_with_meta(1), keyword)
                         .union(exact_match(course_query_with_meta(2), keyword))
                         .union(include_match(course_query_with_meta(3), keyword))
                         .union(fuzzy_match(course_query_with_meta(4), keyword))
                         .union(courseries_match(course_query_with_meta(0), keyword)))
        if union_keywords:
            union_keywords = union_keywords.union(union_courses)
        else:
            union_keywords = union_courses
    ordered_courses = ordering(union_keywords, keywords).group_by(Course.id)

    #courses_count = teacher_match(Course.query, query_str).union(fuzzy_match(Course.query, query_str)).count()

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    if page <= 1:
        page = 1
    num_results = ordered_courses.count()
    selections = ordered_courses.offset((page - 1) * per_page).limit(per_page).all()
    course_objs = [ s[0] for s in selections ]

    pagination = MyPagination(page=page, per_page=per_page, total=num_results, items=course_objs)

    if pagination.total > 0:
        title = '搜索课程「' + query_str + '」'
    # elif noredirect:
    else:
        title = '您的搜索「' + query_str + '」没有匹配到任何课程或老师'
    # else:
        # return search_reviews()
        # print("no result in name sec")
        # return search_reviews_meilisearch()

    search_log = SearchLog()
    search_log.keyword = query_str
    if current_user.is_authenticated:
        search_log.user_id = current_user.id
    search_log.module = 'search_course'
    search_log.page = page
    search_log.save()

    # print(f"search_course: {time.time() - start_time} seconds")
    return render_template('search.html', keyword=query_str, courses=pagination,
                dept=department, deptlist=deptlist,
                title=title,
                this_module='home.search')

@home.route('/search-meilisearch/')
def search_meilisearch():
    ''' meilisearch搜索(仅搜索课程，使用multisearch） '''
    start_time = time.time()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    if page <= 1:
        page = 1
    query_str = request.args.get('q')
    if not query_str:
        return redirect_to_index()
    noredirect = request.args.get('noredirect')

    course_type = request.args.get('type',None,type=int)
    department = request.args.get('dept',None,type=int)
    campus = request.args.get('campus',None,type=str)

    # 构建搜索请求
    # 强制精确搜索教师
    search_params = {
      "queries": [
        {
          "indexUid": "teachers_mysql",
          "q": "\"" + query_str + "\"",
          "attributesToSearchOn": ["name", "email"]
        },
        {
          "indexUid": "courses_mysql",
          "q": query_str,
          "attributesToSearchOn": ["name","course_code"],
          "limit": 100
        },
        {
          "indexUid": "course_terms_mysql",
          "q": query_str,
          "attributesToSearchOn": ["description", "description_eng"]
        }
      ]
    }

    # send search request to MeiliSearch
    meilisearch_api_key = app.config['MEILISEARCH_KEY']
    headers = {
        "Authorization": f"Bearer {meilisearch_api_key}",
        "Content-Type": "application/json"
    }

    # 向MeiliSearch发送请求
    response = requests.post('http://127.0.0.1:7700/multi-search', json=search_params, headers=headers)

    # return the response json
    query_result_json = response.json()

    # extract teacher / course from result

    ## teacher: extract by id in results - hits
    teacher_ids = [hit['id'] for hit in query_result_json['results'][0]['hits']]
    teachers = Teacher.query.filter(Teacher.id.in_(teacher_ids)).all()
    # print(teachers)
    # extract course taught by teacher
    course_ids_from_teacher_search = [course.id for teacher in teachers for course in teacher.courses]
    # course_from_teacher_search = Course.query.filter(Course.id.in_(course_ids_from_teacher_search)).all()
    # print(course_from_teacher_search)

    ## course: extract by id in results - hits
    course_ids_from_name_search = [hit['id'] for hit in query_result_json['results'][1]['hits']]
    # print(course_ids_from_name_search)
    # course_from_name_search = Course.query.filter(Course.id.in_(course_ids_from_name_search)).all()
    # print(course_from_name_search)

    ## course: extract by id in results - hits
    course_ids_from_desc_search = [hit['course_id'] for hit in query_result_json['results'][2]['hits']]
    course_ids_from_desc_search = list(set(course_ids_from_desc_search))
    # course_from_desc_search = Course.query.filter(Course.id.in_(course_ids_from_desc_search)).all()
    # print(course_from_desc_search)

    # merge course ids from 3 search results
    course_ids = course_ids_from_teacher_search + course_ids_from_name_search
    # course_ids = list(set(course_ids))


    # print(course_ids)

    def calculate_normalized_rate(course_rate, avg_rate, avg_rate_count):
        normalized_rate = (course_rate._rate_total + avg_rate * avg_rate_count) / (
                    course_rate.review_count + avg_rate_count)
        return normalized_rate

    # 首先获取平均评分和平均评分次数
    avg_rate = db.session.query(db.func.avg(Review.rate)).scalar()
    avg_rate_count = db.session.query(
        db.func.count(Review.id) / db.func.count(db.func.distinct(Review.course_id))).scalar()

    # 获取课程和评分数据
    merged_courses = Course.query.filter(Course.id.in_(course_ids)).all()
    course_rates = CourseRate.query.filter(CourseRate.id.in_(course_ids)).all()

    # 将 course_rates 转换为字典方便查找
    course_rates_dict = {cr.id: cr for cr in course_rates}

    # 对课程进行排序
    # 先按照归一化评分排序，如果相等，则按照 course_ids 的顺序排序
    merged_courses.sort(key=lambda x: (
    -calculate_normalized_rate(course_rates_dict.get(x.id, None), avg_rate, avg_rate_count), course_ids.index(x.id)))

    merged_courses_page = merged_courses[(page - 1) * per_page: page * per_page]

    pagination = MyPagination(page=page, per_page=per_page, total=len(merged_courses), items=merged_courses_page)

    if pagination.total > 0:
        title = '搜索课程「' + query_str + '」'
    elif noredirect:
        title = '您的搜索「' + query_str + '」没有匹配到任何课程或老师'
    else:
        # return search_reviews()
        # print("no result in name sec")
        return search_reviews_meilisearch()

    search_log = SearchLog()
    search_log.keyword = query_str
    if current_user.is_authenticated:
        search_log.user_id = current_user.id
    search_log.module = 'search_course'
    search_log.page = page
    search_log.save()
    print(f"search_course_meilisearch: {time.time() - start_time} seconds")
    return render_template('search.html', keyword=query_str, courses=pagination,
                dept=department, deptlist=deptlist,
                title=title,
                this_module='home.search')




    # return jsonify(query_result_json)


@home.route('/announcements/')
def announcements():
    announcements = Announcement.query.order_by(Announcement.update_time.desc()).all()
    return render_template('announcements.html', announcements=announcements, title='公告栏')


@home.route('/about/')
def about():
    '''关于我们，网站介绍'''

    first_user = User.query.order_by(User.register_time).limit(1).first()
    today = datetime.now()
    running_days = (today - first_user.register_time).days
    num_users = User.query.count()
    review_count = Review.query.filter(Review.is_hidden == False).filter(Review.is_blocked == False).count()
    course_count = CourseRate.query.filter(CourseRate.review_count > 0).count()
    return render_template('about.html', running_days=running_days, num_users=num_users, review_count=review_count, course_count=course_count, title='关于我们')


@home.route('/report-review/')
def report_review():
    '''report inappropriate review'''

    return render_template('report-review.html', title='投诉点评')


@home.route('/community-rules/')
def community_rules():
    '''社区规范页面'''

    return render_template('community-rules.html', title='社区规范')


@home.route('/report-bug/')
def report_bug():
    ''' 报bug表单 '''

    return render_template('report-bug.html', title='报 bug')


@home.route('/not_found/')
def not_found():
    '''返回404页面'''
    return render_template('404.html', title='404')


@home.route('/songshu/')
def songshu():
    '''Test'''

    return render_template('songshu.html')

@home.route('/robots.txt')
def robots():
    return current_app.send_static_file('robots.txt')

@home.route('/ads.txt')
def google_ads_txt():
    return current_app.send_static_file('ads.txt')