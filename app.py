from flask import Flask, render_template, jsonify, request, redirect, url_for, session, make_response, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import random
import string
from captcha.image import ImageCaptcha
import os

from dotenv import load_dotenv

from flask_mail import Mail, Message
from email_validator import validate_email, EmailNotValidError

import random
from datetime import datetime, timedelta

from flask_limiter import Limiter

from flask_cors import CORS

load_dotenv()

app = Flask(__name__)
CORS(app, origins=['http://localhost:8080'], supports_credentials=True)

app.config['STATIC_FOLDER'] = 'assets'

app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 添加邮件配置
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
# 调试模式下
# app.config['MAIL_SUPPRESS_SEND'] = True
# app.config['MAIL_DEBUG'] = True
# app.config['MAIL_DEFAULT_SENDER'] = 'debug@example.com'

db = SQLAlchemy(app)

mail = Mail(app)

limiter = Limiter(app=app, key_func=lambda: request.remote_addr)

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))

# 添加验证码存储模型
class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    cover = db.Column(db.String(200))
    description = db.Column(db.Text)
    students = db.Column(db.Integer, default=0)
    duration = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.now)

class TestCourse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    cover = db.Column(db.String(200))
    video = db.Column(db.String(200))
    doc = db.Column(db.String(200))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.now)

class TestCourse2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    cover = db.Column(db.String(200))
    video = db.Column(db.String(200))
    doc = db.Column(db.String(200))
    description = db.Column(db.Text)
    brief = db.Column(db.Text)
    avatar = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.now)


# 图形验证码生成
@app.route('/api/v1/captcha')
def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    session['captcha'] = captcha_text
    data = ImageCaptcha().generate(captcha_text)
    return Response(data, content_type='image/png')

@app.route('/api/v1/user/login', methods=['POST'])
def login():
    data = request.get_json()
    account = data.get('account', '')
    password = data.get('password', '')
    captcha = data.get('captcha', '')
    
    # 验证验证码
    if 'captcha' not in session or captcha.upper() != session['captcha'].upper():
        data = { 'code': 40100, 'message': '验证码错误' }
        return jsonify(data)
    
    # 查询用户（邮箱或用户名）
    user = User.query.filter(
        (User.email == account) | (User.username == account)
    ).first()

    if not user or not check_password_hash(user.password, password):
        data = { 'code': 40100, 'message': '用户名或密码错误' }
        return jsonify(data)
    
    session['user'] = user.username
    data = { 'code': 40101, 'message': '登录成功' }
    return jsonify(data)

@app.route('/api/v1/user/logout')
def logout():
    session.pop('user', None)
    return jsonify({'code': 40100, 'message': '已退出登录'})

@app.route('/api/v1/user/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')
    username = data.get('username', '')
    user_code = data.get('verifyCode', '')

    # 验证验证码
    valid_code = VerificationCode.query.filter(
        VerificationCode.email == email,
        VerificationCode.code == user_code,
    ).first()

    if not (valid_code.created_at >= datetime.now() - timedelta(minutes=10)):
        return jsonify({'success': False, 'message': '验证码错误或已过期'})

    # 验证邮箱唯一性
    if User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': '该邮箱已被注册'})

    # 验证邮箱唯一性
    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': '用户名已被使用'})

    # 创建新用户
    new_user = User(
        email=email,
        username=username,
        password=generate_password_hash(password)
    )
    db.session.add(new_user)

    # 删除已使用的验证码
    db.session.delete(valid_code)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/v1/user/current', methods=['GET'])
def current():
    if 'user' in session:
        user = User.query.filter_by(username=session['user']).first()
        return jsonify({
            'email': user.email,
            'username': user.username,
            'code': 40101,
        })
    return jsonify({'username': 'Nobody', 'code': 40100,})

@app.route('/api/v1/user/update', methods=['POST'])
def update():
    data = request.get_json()
    email = data.get('email', '')
    username = data.get('username', '')
    newPassword = data.get('newPassword', '')
    currentPassword = data.get('currentPassword', '')
    user_code = data.get('verifyCode', '')

    # 查询用户
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'success': False, 'message': '用户不存在'})

    # 验证密码
    if not user or not check_password_hash(user.password, currentPassword):
        return jsonify({'success': False, 'message': '密码错误'})

    # 验证验证码
    valid_code = VerificationCode.query.filter(
        VerificationCode.email == email,
        VerificationCode.code == user_code,
    ).first()

    if not (valid_code.created_at >= datetime.now() - timedelta(minutes=10)):
        return jsonify({'success': False, 'message': '验证码错误或已过期'})

    # 删除已使用的验证码
    db.session.delete(valid_code)

    # 更新用户信息
    user.username = username
    user.password = generate_password_hash(newPassword)
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/api/v1/sendCode', methods=['POST'])
@limiter.limit("5/hour")  # 同一IP每小时最多5次
def send_verification_code():
    data = request.get_json()
    email = data.get('email', '').strip()

    try:
        # 验证邮箱格式
        valid = validate_email(email)
        email = valid.email
    except EmailNotValidError:
        return jsonify({'success': False, 'message': '无效的邮箱地址'})

    # 生成验证码
    code = generate_verification_code()
    
    # 存储验证码（先删除旧验证码）
    VerificationCode.query.filter_by(email=email).delete()
    new_code = VerificationCode(email=email, code=code)
    db.session.add(new_code)
    db.session.commit()

    # 发送邮件
    try:
        msg = Message(
            subject="您的注册验证码",
            recipients=[email],
            html='email_template.html',
        )
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        print(e)
        return jsonify({'success': False, 'message': '邮件发送失败'})

@app.route('/api/v1/course/all')
def course_list():
    courses = TestCourse2.query.all()
    if courses:
        return jsonify({
            'data': [{
                'id': course.id,
                'title': course.title,
                'cover': course.cover,
                'brief': course.brief,
                'avatar': course.avatar,
                'description': course.description,
                'created_at': course.created_at
                } for course in courses],
            'success': True})
    return jsonify({'success': False, 'message': '未查询到课程'})

@app.route('/api/v1/course/<int:course_id>')
def course_detail(course_id):
    course = TestCourse2.query.filter(TestCourse2.id == course_id).first()
    if course:
        return jsonify({
            'success': True,
            'title': course.title,
            'cover': course.cover,
            'video': course.video,
            'doc': course.doc,
            'description': course.description,
            'created_at': course.created_at,
        })
    return jsonify({'success': False, 'message': '课程不存在'})

@app.route('/api/v1/carousel')
def carousel():
    return jsonify({
        'data': [
            'http://localhost:5000/static/carousels/Carousel1.jpg',
            'http://localhost:5000/static/carousels/Carousel2.png',
            'http://localhost:5000/static/carousels/Carousel3.png',
            'http://localhost:5000/static/carousels/Carousel4.png',
        ],
        'success': True,
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)