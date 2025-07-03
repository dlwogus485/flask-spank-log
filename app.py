# -*- coding: utf-8 -*-
import os
from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, flash, jsonify
from datetime import datetime, timedelta, date
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, extract, and_
import json 

# Flask 애플리케이션 초기화
app = Flask(__name__)

# 시크릿 키 설정 (세션 관리에 필수)
# 실제 서비스에서는 환경 변수 등으로 관리하는 것이 강력히 권장됩니다.
app.secret_key = 'your_very_strong_and_secret_key_here_for_production_use' 

# 데이터베이스 설정
# SQLite 데이터베이스 파일을 'instance' 폴더에 'site.db'로 생성합니다.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)

# 이미지 업로드 설정
UPLOAD_FOLDER = 'static/uploads' 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} 

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 데이터베이스 모델 정의

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False) 

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Report(db.Model):
    """
    기상톡(Morning Talk) 보고서를 저장하는 모델입니다.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    is_late = db.Column(db.Boolean, default=False) # 10시 이후 제출 여부

    user = db.relationship('User', backref=db.backref('reports', lazy=True))

    def __repr__(self):
        return f'<Report {self.id} by {self.user.username}>'

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('payments', lazy=True))

    def __repr__(self):
        return f'<Payment {self.id} by {self.user.username} - {self.amount}>'

class BookReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_title = db.Column(db.String(255), nullable=False)
    page_count = db.Column(db.Integer, nullable=True)
    review_content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(120), nullable=True) 
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('book_reviews', lazy=True))

    def __repr__(self):
        return f'<BookReview {self.id} by {self.user.username} - {self.book_title}>'

class Cardio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False) 
    image_filename = db.Column(db.String(120), nullable=True) 
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False) 

    user = db.relationship('User', backref=db.backref('cardio_logs', lazy=True))

    def __repr__(self):
        return f'<Cardio {self.id} by {self.user.username} - {self.date}>'

class WeightEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    weight_kg = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('weight_entries', lazy=True))

    def __repr__(self):
        return f'<WeightEntry {self.id} by {self.user.username} - {self.weight_kg}kg>'

class MealLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    meal_type = db.Column(db.String(20), nullable=False) 
    image_filename = db.Column(db.String(120), nullable=True) 
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('meal_logs', lazy=True))

    def __repr__(self):
        return f'<MealLog {self.id} by {self.user.username} - {self.meal_type}>'

class Penalty(db.Model):
    """
    벌점 내역을 저장하는 모델입니다.
    - id: 고유 식별자
    - user_id: 벌점을 받은 사용자 ID
    - penalty_type: 벌점 유형 (예: '기상톡 지각', '기상톡 미제출', '소액결제 한도 초과', '금지 멘트 사용', '독후감 미달', '유산소 미달', '체중 증가')
    - rule_name: 벌점이 부과된 규칙 이름 (예: '기상톡', '소액결제')
    - reason: 벌점 상세 이유
    - penalty_points: 부과된 벌점 (예: 1점)
    - timestamp: 벌점 부과 시간
    - related_date: 벌점과 관련된 날짜 (예: 미제출 기상톡의 날짜)
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    penalty_type = db.Column(db.String(50), nullable=False)
    rule_name = db.Column(db.String(50), nullable=True) # 벌점이 부과된 규칙 이름
    reason = db.Column(db.Text, nullable=True)
    penalty_points = db.Column(db.Integer, nullable=False, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    related_date = db.Column(db.Date, nullable=True) # 주간/일간 벌점 계산 시 해당 날짜/주차를 기록

    user = db.relationship('User', backref=db.backref('penalties', lazy=True))

    def __repr__(self):
        return f'<Penalty {self.id} for {self.user.username} - {self.penalty_type}>'

class Reflection(db.Model):
    """
    반성문 및 교육 요청 기록을 저장하는 모델입니다.
    - id: 고유 식별자
    - user_id: 반성문을 제출한 사용자 ID
    - reflection_content: 반성문 내용
    - request_education: 교육 요청 여부 (True/False)
    - spanking_tool: 선택된 스팽킹 도구 (예: '손바닥', '패들')
    - timestamp: 제출 시간
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reflection_content = db.Column(db.Text, nullable=False)
    request_education = db.Column(db.Boolean, default=False)
    spanking_tool = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('reflections', lazy=True))

    def __repr__(self):
        return f'<Reflection {self.id} by {self.user.username}>'


# 데이터베이스 초기화 함수
def init_db():
    """
    애플리케이션 시작 시 데이터베이스 테이블을 생성하고,
    초기 사용자 (master, ddang)를 추가합니다.
    """
    with app.app_context():
        db.create_all() # 모든 모델에 해당하는 테이블 생성

        # 초기 사용자 추가 (이미 존재하지 않을 경우에만)
        if not User.query.filter_by(username='master').first():
            master = User(username='master', role='owner')
            master.set_password('secret')
            db.session.add(master)
        if not User.query.filter_by(username='ddang').first():
            ddang = User(username='ddang', role='sub')
            ddang.set_password('submit')
            db.session.add(ddang)
        db.session.commit()

# 파일 업로드 유틸리티 함수
def allowed_file(filename):
    """
    업로드된 파일의 확장자가 허용된 확장자 목록에 있는지 확인합니다.
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
    """
    업로드된 파일을 안전한 이름으로 저장하고, 저장된 파일명을 반환합니다.
    """
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # 파일명 중복 방지를 위해 현재 시간을 파일명에 추가합니다.
        unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        return unique_filename
    return None

# ---------------------------------------------------
# 인증 및 기본 라우트
# ---------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    """사용자 로그인 페이지를 처리합니다."""
    if request.method == 'POST':
        uid = request.form.get('username')
        pwd = request.form.get('password')
        user = User.query.filter_by(username=uid).first() 

        if user and user.check_password(pwd): 
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash(f"환영합니다, {user.username}님!", 'success')
            return redirect(url_for('home'))
        else:
            flash("잘못된 로그인 정보입니다.", 'error') 
            return render_template('login.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    """사용자 세션을 종료하고 로그아웃 처리합니다."""
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash("로그아웃 되었습니다.", 'info')
    return redirect(url_for('login'))

@app.route('/')
def home():
    """
    로그인 상태에 따라 'owner'는 대시보드, 'sub'는 메인 기능 선택 페이지로 리다이렉트합니다.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') == 'owner':
        # 'owner'는 모든 보고서 및 기록의 최근 10개 항목을 조회하여 대시보드에 표시합니다.
        all_reports = Report.query.order_by(Report.timestamp.desc()).limit(10).all()
        all_payments = Payment.query.order_by(Payment.timestamp.desc()).limit(10).all()
        all_book_reviews = BookReview.query.order_by(BookReview.timestamp.desc()).limit(10).all()
        all_cardio_logs = Cardio.query.order_by(Cardio.timestamp.desc()).limit(10).all()
        all_weight_entries = WeightEntry.query.order_by(WeightEntry.timestamp.desc()).limit(10).all()
        all_meal_logs = MealLog.query.order_by(MealLog.timestamp.desc()).limit(10).all()
        all_penalties = Penalty.query.order_by(Penalty.timestamp.desc()).limit(10).all() # 최근 벌점 추가
        all_reflections = Reflection.query.order_by(Reflection.timestamp.desc()).limit(10).all() # 최근 반성문 추가

        return render_template('dashboard.html',
                               reports=all_reports,
                               payments=all_payments,
                               book_reviews=all_book_reviews,
                               cardio_logs=all_cardio_logs,
                               weight_entries=all_weight_entries,
                               meal_logs=all_meal_logs,
                               penalties=all_penalties, # 벌점 데이터 추가
                               reflections=all_reflections) # 반성문 데이터 추가
    else:
        # 'sub' 사용자는 기능 선택 페이지로 이동합니다.
        # 누적 벌점 5점 이상일 때 5의 배수에서만 경고 팝업 표시
        user_id = session['user_id']
        total_penalty_points = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=user_id).scalar() or 0
        # 0점 초과하고 5의 배수일 때만 팝업 표시
        show_penalty_warning = (total_penalty_points > 0 and total_penalty_points % 5 == 0)

        return render_template('index.html', show_penalty_warning=show_penalty_warning) 

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    'static/uploads' 폴더에 저장된 이미지 파일을 웹에서 접근할 수 있도록 제공합니다.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------------------------------------------
# 기상톡 (Morning Talk) 기능
# ---------------------------------------------------
@app.route('/morning_talk', methods=['GET', 'POST'])
def morning_talk():
    """
    기상톡 제출 페이지를 처리하고, 제출 시 지각 여부에 따라 벌점을 부과합니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("기상톡을 제출할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    today = datetime.now().date()

    # 이미 오늘 기상톡을 제출했는지 확인
    existing_morning_talk = Report.query.filter(
        Report.user_id == user_id,
        func.date(Report.timestamp) == today
    ).first()

    if request.method == 'POST':
        if existing_morning_talk:
            flash("오늘은 이미 기상톡을 제출하셨습니다.", 'warning')
            return redirect(url_for('morning_talk'))

        talk_content = request.form.get('morning_talk_content')
        now = datetime.now()
        
        # "용서 금지 멘트" 필터링
        forbidden_phrase = "한번만 봐주세요"
        if forbidden_phrase in talk_content:
            flash(f"'{forbidden_phrase}' 문구는 사용할 수 없습니다. 다시 작성해주세요.", 'warning')
            # 금지 멘트 사용 벌점 부과
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type='금지 멘트 사용',
                rule_name='기상톡',
                reason=f"기상톡 내용에 금지 멘트 '{forbidden_phrase}' 포함",
                penalty_points=1 
            )
            db.session.add(new_penalty)
            db.session.commit() # 벌점 즉시 반영
            return redirect(url_for('morning_talk'))

        is_late = False
        if now.hour >= 10: # 10시 (오전 10시) 이후
            flash("10시 이후에 기상톡을 제출하셨습니다. 지각 벌점이 부과됩니다.", 'warning')
            is_late = True
            # 지각 벌점 부과
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type='기상톡 지각',
                rule_name='기상톡',
                reason=f"10시 이후 기상톡 제출: {now.strftime('%H:%M')}",
                penalty_points=1 # 벌점 1점
            )
            db.session.add(new_penalty)

        new_morning_talk = Report(
            user_id=user_id,
            content=talk_content,
            timestamp=now,
            is_late=is_late
        )
        db.session.add(new_morning_talk)
        db.session.commit()

        flash("기상톡이 성공적으로 제출되었습니다!", 'success')
        return redirect(url_for('morning_talk'))
    
    # GET 요청 시 템플릿 렌더링
    return render_template('morning_talk.html', 
                           existing_morning_talk=existing_morning_talk) # 오늘 제출 여부 전달

@app.route('/morning_talk_history')
def morning_talk_history():
    """
    현재 로그인한 사용자의 기상톡 제출 이력을 조회합니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("이력을 조회할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_reports = Report.query.filter_by(user_id=session['user_id']).order_by(Report.timestamp.desc()).all()
    return render_template('morning_talk_history.html', reports=user_reports)

@app.route('/delete_morning_talk_selected', methods=['POST'])
def delete_morning_talk_selected():
    """
    선택된 기상톡 기록을 삭제합니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("기상톡을 삭제할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    selected_report_ids = request.form.getlist('delete_ids') 
    
    for report_id in selected_report_ids:
        report_to_delete = Report.query.get(report_id)
        if report_to_delete and report_to_delete.user_id == session['user_id']:
            db.session.delete(report_to_delete)
    
    db.session.commit()
    flash("선택된 기상톡이 삭제되었습니다.", 'success')
    return redirect(url_for('morning_talk_history'))

# ---------------------------------------------------
# 벌점 관리 기능
# ---------------------------------------------------
@app.route('/penalties')
def penalties():
    """
    사용자의 벌점 내역을 조회하고 총 벌점을 표시합니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("벌점 내역을 조회할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # 날짜 필터링 (기본: 전체, 요청 시 특정 월/일)
    filter_year = request.args.get('year', type=int)
    filter_month = request.args.get('month', type=int)
    filter_day = request.args.get('day', type=int)

    query = Penalty.query.filter_by(user_id=user_id)

    if filter_year:
        query = query.filter(extract('year', Penalty.timestamp) == filter_year)
    if filter_month:
        query = query.filter(extract('month', Penalty.timestamp) == filter_month)
    if filter_day:
        query = query.filter(extract('day', Penalty.timestamp) == filter_day)

    user_penalties = query.order_by(Penalty.timestamp.desc()).all()
    total_penalty_points = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=user_id).scalar() or 0

    # 필터링 옵션 제공을 위한 년/월 목록
    available_years = db.session.query(extract('year', Penalty.timestamp)).distinct().order_by(extract('year', Penalty.timestamp).desc()).all()
    available_months = db.session.query(extract('month', Penalty.timestamp)).distinct().order_by(extract('month', Penalty.timestamp)).all()

    return render_template('penalties.html', 
                           penalties=user_penalties, 
                           total_penalty_points=total_penalty_points,
                           available_years=[y[0] for y in available_years],
                           available_months=[m[0] for m in available_months],
                           selected_year=filter_year,
                           selected_month=filter_month,
                           selected_day=filter_day)

@app.route('/check_daily_weekly_penalties', methods=['POST'])
def check_daily_weekly_penalties():
    """
    미제출된 기상톡, 주간 미달 규칙(유산소, 독후감)에 대해 벌점을 부과하는 수동 트리거입니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("벌점 확인 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    now = datetime.now()
    today = now.date()
    
    # --- 1. 기상톡 미제출 벌점 확인 (오늘 날짜 기준) ---
    # 10시가 넘었는지 확인
    if now.hour >= 10:
        # 오늘 기상톡을 제출했는지 확인
        morning_talk_submitted_today = Report.query.filter(
            Report.user_id == user_id,
            func.date(Report.timestamp) == today
        ).first()

        # 오늘 미제출 벌점이 이미 부과되었는지 확인
        penalty_already_issued = Penalty.query.filter(
            Penalty.user_id == user_id,
            Penalty.penalty_type == '기상톡 미제출',
            func.date(Penalty.timestamp) == today
        ).first()

        if not morning_talk_submitted_today and not penalty_already_issued:
            # 오늘 기상톡을 제출하지 않았고, 아직 벌점도 부과되지 않았다면 벌점 부과
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type='기상톡 미제출',
                rule_name='기상톡',
                reason=f"오늘 기상톡 미제출 ({today.strftime('%Y-%m-%d')})",
                penalty_points=2 # 미제출 벌점 (지각보다 높게 설정)
            )
            db.session.add(new_penalty)
            flash("오늘 기상톡 미제출로 벌점이 부과되었습니다.", 'warning')
    else:
        flash("아직 10시가 지나지 않았습니다. 기상톡 미제출 벌점은 10시 이후에 확인할 수 있습니다.", 'info')

    # --- 2. 지난 주 유산소 운동 벌점 확인 ---
    # 지난주 월요일부터 일요일까지의 기간을 계산
    last_week_end = today - timedelta(days=today.weekday() + 1) # 지난주 일요일
    last_week_start = last_week_end - timedelta(days=6) # 지난주 월요일

    # 해당 주차에 대한 벌점 부과 여부 확인 (중복 방지)
    # related_date를 지난주 월요일로 기록하여 해당 주차에 대한 벌점임을 식별
    penalty_for_last_week_cardio_issued = Penalty.query.filter(
        Penalty.user_id == user_id,
        Penalty.penalty_type.like('유산소 미달%'),
        Penalty.related_date == last_week_start # 해당 주차의 시작 날짜로 식별
    ).first()

    if not penalty_for_last_week_cardio_issued:
        last_week_cardio_count = Cardio.query.filter(
            Cardio.user_id == user_id,
            Cardio.date >= last_week_start,
            Cardio.date <= last_week_end
        ).count()

        penalty_points = 0
        reason = ""
        if last_week_cardio_count == 2:
            penalty_points = 1
            reason = f"지난주 유산소 2회 수행 (목표 3회)"
        elif last_week_cardio_count == 1:
            penalty_points = 2
            reason = f"지난주 유산소 1회 수행 (목표 3회)"
        elif last_week_cardio_count == 0:
            penalty_points = 3
            reason = f"지난주 유산소 0회 수행 (목표 3회)"
        
        if penalty_points > 0:
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type=f'유산소 미달 ({last_week_cardio_count}회)',
                rule_name='유산소',
                reason=reason,
                penalty_points=penalty_points,
                related_date=last_week_start # 벌점 부과된 주차의 시작 날짜 기록
            )
            db.session.add(new_penalty)
            flash(f"지난주 유산소 운동 미달로 벌점 {penalty_points}점이 부과되었습니다.", 'warning')

    # --- 3. 지난 주 독후감 벌점 확인 ---
    # 지난주 월요일부터 일요일까지의 기간을 계산
    penalty_for_last_week_book_review_issued = Penalty.query.filter(
        Penalty.user_id == user_id,
        Penalty.penalty_type.like('독후감 미달%'),
        Penalty.related_date == last_week_start # 해당 주차의 시작 날짜로 식별
    ).first()

    if not penalty_for_last_week_book_review_issued:
        last_week_book_review_count = BookReview.query.filter(
            BookReview.user_id == user_id,
            BookReview.timestamp >= last_week_start,
            BookReview.timestamp <= last_week_end + timedelta(days=1, seconds=-1) # 일요일 23:59:59까지 포함
        ).count()

        penalty_points = 0
        reason = ""
        if last_week_book_review_count == 2:
            penalty_points = 1
            reason = f"지난주 독후감 2회 제출 (목표 3회)"
        elif last_week_book_review_count == 1:
            penalty_points = 2
            reason = f"지난주 독후감 1회 제출 (목표 3회)"
        elif last_week_book_review_count == 0:
            penalty_points = 3
            reason = f"지난주 독후감 0회 제출 (목표 3회)"
        
        if penalty_points > 0:
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type=f'독후감 미달 ({last_week_book_review_count}회)',
                rule_name='독후감',
                reason=reason,
                penalty_points=penalty_points,
                related_date=last_week_start # 벌점 부과된 주차의 시작 날짜 기록
            )
            db.session.add(new_penalty)
            flash(f"지난주 독후감 미달로 벌점 {penalty_points}점이 부과되었습니다.", 'warning')

    db.session.commit() # 모든 벌점 일괄 커밋
    flash("벌점 확인이 완료되었습니다.", 'info')
    return redirect(url_for('penalties'))

# ---------------------------------------------------
# 반성문 / 교육 요청 기능
# ---------------------------------------------------
@app.route('/reflection_submission', methods=['GET', 'POST'])
def reflection_submission():
    """
    반성문 및 교육 요청을 제출하는 페이지입니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("반성문을 제출할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        reflection_content = request.form.get('reflection_content')
        request_education = 'request_education' in request.form # 체크박스 여부
        spanking_tool = request.form.get('spanking_tool')

        if not reflection_content:
            flash("반성문 내용은 필수입니다.", 'error')
            return redirect(url_for('reflection_submission'))
        
        new_reflection = Reflection(
            user_id=session['user_id'],
            reflection_content=reflection_content,
            request_education=request_education,
            spanking_tool=spanking_tool
        )
        db.session.add(new_reflection)
        db.session.commit()
        flash("반성문이 성공적으로 제출되었습니다.", 'success')
        return redirect(url_for('home')) # 제출 후 홈으로 이동

    spanking_tools = ['손바닥', '패들', '벨트', '회초리', '기타']
    return render_template('reflection_submission.html', spanking_tools=spanking_tools)

@app.route('/reflection_history')
def reflection_history():
    """
    제출된 반성문 기록을 조회합니다. (master는 전체, sub는 본인 기록)
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') == 'owner':
        reflections = Reflection.query.order_by(Reflection.timestamp.desc()).all()
    else: # sub
        reflections = Reflection.query.filter_by(user_id=session['user_id']).order_by(Reflection.timestamp.desc()).all()
    
    return render_template('reflection_history.html', reflections=reflections)


# ---------------------------------------------------
# 기타 생활 습관 관리 기능 (이전과 동일)
# ---------------------------------------------------

@app.route('/payments', methods=['GET', 'POST'])
def payments():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if request.method == 'POST':
        amount = request.form.get('amount', type=int)
        description = request.form.get('description')
        
        if not amount or amount <= 0:
            flash("유효한 금액을 입력해주세요.", 'error')
            return redirect(url_for('payments'))

        new_payment = Payment(user_id=user_id, amount=amount, description=description)
        db.session.add(new_payment)
        db.session.commit()
        flash("결제 내역이 기록되었습니다.", 'success')
        
        # 소액결제 한도 초과 시 벌점 부과 (즉시 확인)
        current_month = datetime.now().month
        current_year = datetime.now().year
        monthly_total = db.session.query(func.sum(Payment.amount)).filter(
            Payment.user_id == user_id,
            extract('year', Payment.timestamp) == current_year,
            extract('month', Payment.timestamp) == current_month
        ).scalar() or 0
        limit = 500000 
        if monthly_total > limit:
            # 이미 이번 달 한도 초과 벌점이 부과되었는지 확인 (월별 1회)
            penalty_already_issued = Penalty.query.filter(
                Penalty.user_id == user_id,
                Penalty.penalty_type == '소액결제 한도 초과',
                extract('year', Penalty.timestamp) == current_year,
                extract('month', Penalty.timestamp) == current_month
            ).first()
            if not penalty_already_issued:
                new_penalty = Penalty(
                    user_id=user_id,
                    penalty_type='소액결제 한도 초과',
                    rule_name='소액결제',
                    reason=f"월 소액결제 한도({limit:,.0f}원) 초과: 현재 {monthly_total:,.0f}원",
                    penalty_points=1 # 벌점 1점
                )
                db.session.add(new_penalty)
                db.session.commit()
                flash("월 소액결제 한도 초과로 벌점이 부과되었습니다!", 'error')

        return redirect(url_for('payments'))

    current_month = datetime.now().month
    current_year = datetime.now().year

    monthly_payments = Payment.query.filter(
        Payment.user_id == user_id,
        extract('year', Payment.timestamp) == current_year,
        extract('month', Payment.timestamp) == current_month
    ).order_by(Payment.timestamp.desc()).all()

    monthly_total = db.session.query(func.sum(Payment.amount)).filter(
        Payment.user_id == user_id,
        extract('year', Payment.timestamp) == current_year,
        extract('month', Payment.timestamp) == current_month
    ).scalar() or 0

    limit = 500000 
    if monthly_total > limit:
        flash(f"이번 달 소액결제({monthly_total:,.0f}원)가 한도({limit:,.0f}원)를 초과했습니다!", 'warning')

    return render_template('payments.html', 
                           monthly_payments=monthly_payments, 
                           monthly_total=monthly_total,
                           limit=limit)

@app.route('/book_reviews', methods=['GET', 'POST'])
def book_reviews():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        book_title = request.form.get('book_title')
        page_count = request.form.get('page_count', type=int)
        review_content = request.form.get('review_content')
        image_file = request.files.get('image')

        image_filename = save_uploaded_file(image_file) 

        if image_file and not image_filename: 
            flash("허용되지 않는 파일 형식입니다. (png, jpg, jpeg, gif만 가능)", 'warning')
            return redirect(url_for('book_reviews'))
        
        if not book_title or not review_content:
            flash("책 제목과 감상문은 필수 입력 사항입니다.", 'error')
            return redirect(url_for('book_reviews'))
        
        # 감상문 30자 이상 조건
        if len(review_content) < 30:
            flash("감상문은 30자 이상 작성해야 합니다. 벌점이 부과됩니다.", 'warning')
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type='독후감 내용 미달',
                rule_name='독후감',
                reason=f"감상문 30자 미만 ({len(review_content)}자)",
                penalty_points=1 
            )
            db.session.add(new_penalty)
            db.session.commit()


        new_review = BookReview(
            user_id=user_id,
            book_title=book_title,
            page_count=page_count,
            review_content=review_content,
            image_filename=image_filename
        )
        db.session.add(new_review)
        db.session.commit()
        flash("독후감이 성공적으로 제출되었습니다.", 'success')
        return redirect(url_for('book_reviews'))

    user_reviews = BookReview.query.filter_by(user_id=user_id).order_by(BookReview.timestamp.desc()).all()
    
    total_reviews = len(user_reviews)
    total_pages_read = db.session.query(func.sum(BookReview.page_count)).filter(BookReview.user_id == user_id).scalar() or 0

    return render_template('book_reviews.html', 
                           reviews=user_reviews,
                           total_reviews=total_reviews,
                           total_pages_read=total_pages_read)

@app.route('/cardio', methods=['GET', 'POST'])
def cardio():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        cardio_date_str = request.form.get('cardio_date')
        image_file = request.files.get('image')
        
        try:
            cardio_date = datetime.strptime(cardio_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("유효한 날짜 형식을 입력해주세요 (YYYY-MM-DD).", 'error')
            return redirect(url_for('cardio'))

        image_filename = save_uploaded_file(image_file) 

        if image_file and not image_filename: 
            flash("허용되지 않는 파일 형식입니다. (png, jpg, jpeg, gif만 가능)", 'warning')
            return redirect(url_for('cardio'))
        
        existing_log = Cardio.query.filter_by(user_id=user_id, date=cardio_date).first()
        if existing_log:
            flash(f"{cardio_date_str} 날짜의 유산소 기록이 이미 존재합니다. 수정하거나 다른 날짜를 선택해주세요.", 'warning')
            return redirect(url_for('cardio'))

        new_cardio = Cardio(user_id=user_id, date=cardio_date, image_filename=image_filename)
        db.session.add(new_cardio)
        db.session.commit()
        flash("유산소 운동이 기록되었습니다.", 'success')
        return redirect(url_for('cardio'))

    today = datetime.now().date()
    start_of_week = today - timedelta(days=today.weekday()) 
    end_of_week = start_of_week + timedelta(days=6)

    weekly_dates = [start_of_week + timedelta(days=i) for i in range(7)]

    weekly_cardio_logs = Cardio.query.filter(
        Cardio.user_id == user_id,
        Cardio.date >= start_of_week,
        Cardio.date <= end_of_week
    ).order_by(Cardio.date).all()

    weekly_count = len(weekly_cardio_logs)
    
    recent_logs = Cardio.query.filter_by(user_id=user_id).order_by(Cardio.timestamp.desc()).limit(7).all()

    return render_template('cardio.html',
                           weekly_cardio_logs=weekly_cardio_logs,
                           start_of_week=start_of_week,
                           end_of_week=end_of_week,
                           weekly_count=weekly_count,
                           recent_logs=recent_logs,
                           weekly_dates=weekly_dates) 

@app.route('/weight', methods=['GET', 'POST'])
def weight():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        weight_kg = request.form.get('weight_kg', type=float)
        
        if not weight_kg or weight_kg <= 0:
            flash("유효한 체중을 입력해주세요.", 'error')
            return redirect(url_for('weight'))

        new_weight_entry = WeightEntry(user_id=user_id, weight_kg=weight_kg)
        db.session.add(new_weight_entry)
        db.session.commit()
        flash("체중이 기록되었습니다.", 'success')

        # 2주간 1kg 이상 증가 시 벌점 부과
        user_weight_entries = WeightEntry.query.filter_by(user_id=user_id).order_by(WeightEntry.timestamp.asc()).all()
        if len(user_weight_entries) >= 2:
            two_weeks_ago = datetime.now() - timedelta(weeks=2)
            recent_entries = WeightEntry.query.filter(
                WeightEntry.user_id == user_id,
                WeightEntry.timestamp >= two_weeks_ago
            ).order_by(WeightEntry.timestamp.asc()).all()
            
            if len(recent_entries) >= 2:
                first_weight_in_period = recent_entries[0].weight_kg
                last_weight_in_period = recent_entries[-1].weight_kg
                
                weight_change = last_weight_in_period - first_weight_in_period
                
                if weight_change > 1.0: 
                    # 이미 해당 날짜에 벌점이 부과되었는지 확인 (하루에 한 번만)
                    penalty_already_issued = Penalty.query.filter(
                        Penalty.user_id == user_id,
                        Penalty.penalty_type == '체중 증가',
                        func.date(Penalty.timestamp) == date.today()
                    ).first()
                    if not penalty_already_issued:
                        new_penalty = Penalty(
                            user_id=user_id,
                            penalty_type='체중 증가',
                            rule_name='체중 관리',
                            reason=f"최근 2주간 체중 {weight_change:.1f}kg 증가 (1kg 초과)",
                            penalty_points=5 # 높은 벌점
                        )
                        db.session.add(new_penalty)
                        db.session.commit()
                        flash("경고: 최근 2주간 체중이 1kg 이상 증가하여 벌점이 부과되었습니다!", 'error')


        return redirect(url_for('weight'))

    user_weight_entries = WeightEntry.query.filter_by(user_id=user_id).order_by(WeightEntry.timestamp.asc()).all()
    
    labels = [entry.timestamp.strftime('%m-%d') for entry in user_weight_entries]
    data = [entry.weight_kg for entry in user_weight_entries]
    
    warning_message = None
    if len(user_weight_entries) >= 2:
        two_weeks_ago = datetime.now() - timedelta(weeks=2)
        recent_entries = WeightEntry.query.filter(
            WeightEntry.user_id == user_id,
            WeightEntry.timestamp >= two_weeks_ago
        ).order_by(WeightEntry.timestamp.asc()).all()
        
        if len(recent_entries) >= 2:
            first_weight_in_period = recent_entries[0].weight_kg
            last_weight_in_period = recent_entries[-1].weight_kg
            
            weight_change = last_weight_in_period - first_weight_in_period
            
            if weight_change > 1.0: 
                warning_message = f"경고: 최근 2주간 체중이 {weight_change:.1f}kg 증가하여 1kg 초과 기준을 넘었습니다."
                flash(warning_message, 'warning')

    return render_template('weight.html', 
                           weight_entries=user_weight_entries,
                           chart_labels=json.dumps(labels), 
                           chart_data=json.dumps(data),
                           warning_message=warning_message)

@app.route('/meal_logs', methods=['GET', 'POST'])
def meal_logs():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        meal_type = request.form.get('meal_type')
        image_file = request.files.get('image')

        if meal_type not in ['breakfast', 'lunch', 'dinner']:
            flash("유효한 끼니 구분을 선택해주세요.", 'error')
            return redirect(url_for('meal_logs'))

        image_filename = save_uploaded_file(image_file) 

        if not image_filename: 
            flash("식사 인증샷은 필수이며, 허용되는 파일 형식(png, jpg, jpeg, gif)이어야 합니다.", 'error')
            return redirect(url_for('meal_logs'))

        new_meal_log = MealLog(user_id=user_id, meal_type=meal_type, image_filename=image_filename)
        db.session.add(new_meal_log)
        db.session.commit()
        flash(f"{meal_type} 식사 인증이 기록되었습니다.", 'success')
        return redirect(url_for('meal_logs'))

    user_meal_logs = MealLog.query.filter_by(user_id=user_id).order_by(MealLog.timestamp.desc()).all()
    
    return render_template('meal_logs.html', meal_logs=user_meal_logs)


# 애플리케이션 실행 진입점
if __name__ == '__main__':
    init_db()
    print("Flask 서버 실행 중! http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)


