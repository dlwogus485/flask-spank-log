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
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dbd0cfe42026f704b2829aa295c15f4c5698c9fa033ebac7') 

# 데이터베이스 설정
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
db = SQLAlchemy(app)

# 이미지 업로드 설정
UPLOAD_FOLDER = 'static/uploads' 
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf'} # PDF 허용 추가

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

class CommuteAuthReport(db.Model): # Report -> CommuteAuthReport로 변경
    """
    출근인증 보고서를 저장하는 모델입니다.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    is_late = db.Column(db.Boolean, default=False) # 10시 이후 제출 여부 (지각 체크박스에 따라)
    is_holiday = db.Column(db.Boolean, default=False) # 휴무일 여부 추가

    user = db.relationship('User', backref=db.backref('commute_auth_reports', lazy=True))

    def __repr__(self):
        return f'<CommuteAuthReport {self.id} by {self.user.username}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'is_late': self.is_late,
            'is_holiday': self.is_holiday, # 필드 추가
            'username': self.user.username if self.user else None
        }

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    image_filename = db.Column(db.String(120), nullable=False) # 명세서 사진 필수
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('payments', lazy=True))

    def __repr__(self):
        return f'<Payment {self.id} by {self.user.username} - {self.amount}>'

# BookReview 모델 제거
# class BookReview(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     book_title = db.Column(db.String(255), nullable=False)
#     page_count = db.Column(db.Integer, nullable=True)
#     review_content = db.Column(db.Text, nullable=False)
#     image_filename = db.Column(db.String(120), nullable=True) 
#     timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

#     user = db.relationship('User', backref=db.backref('book_reviews', lazy=True))

#     def __repr__(self):
#         return f'<BookReview {self.id} by {self.user.username} - {self.book_title}>'

class Cardio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False) 
    image_filename = db.Column(db.String(120), nullable=False) # 사진 업로드 필수
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

# MealLog 모델 제거
# class MealLog(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
#     meal_type = db.Column(db.String(20), nullable=False) 
#     image_filename = db.Column(db.String(120), nullable=True) 
#     timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

#     user = db.relationship('User', backref=db.backref('meal_logs', lazy=True))

#     def __repr__(self):
#         return f'<MealLog {self.id} by {self.user.username} - {self.meal_type}>'

class Penalty(db.Model):
    """
    벌점 내역을 저장하는 모델입니다.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    penalty_type = db.Column(db.String(50), nullable=False)
    rule_name = db.Column(db.String(50), nullable=True) 
    reason = db.Column(db.Text, nullable=True)
    penalty_points = db.Column(db.Integer, nullable=False, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    related_date = db.Column(db.Date, nullable=True) # 벌점과 관련된 날짜 (주간/월간 벌점 계산 시 해당 날짜/주차를 기록)

    user = db.relationship('User', backref=db.backref('penalties', lazy=True))

    def __repr__(self):
        return f'<Penalty {self.id} for {self.user.username} - {self.penalty_type}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'penalty_type': self.penalty_type,
            'rule_name': self.rule_name,
            'reason': self.reason,
            'penalty_points': self.penalty_points,
            'timestamp': self.timestamp.isoformat(),
            'related_date': self.related_date.isoformat() if self.related_date else None,
            'username': self.user.username if self.user else None
        }

class PunishmentSchedule(db.Model):
    """
    체벌/교육 일정 요청 및 확정 기록을 저장하는 모델입니다.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requested_datetime = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    requested_tool = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default='pending', nullable=False) 
    admin_notes = db.Column(db.Text, nullable=True)
    approved_datetime = db.Column(db.DateTime, nullable=True) 
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('punishment_schedules', lazy=True))

    def __repr__(self):
        return f'<PunishmentSchedule {self.id} by {self.user.username} - {self.status}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'requested_datetime': self.requested_datetime.isoformat(),
            'reason': self.reason,
            'requested_tool': self.requested_tool,
            'status': self.status,
            'admin_notes': self.admin_notes,
            'approved_datetime': self.approved_datetime.isoformat() if self.approved_datetime else None,
            'timestamp': self.timestamp.isoformat(),
            'username': self.user.username if self.user else None
        }

class PenaltyResetHistory(db.Model):
    """
    벌점 리셋 이력을 저장하는 모델입니다.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reset_date = db.Column(db.Date, nullable=False) 
    reset_reason = db.Column(db.String(100), nullable=False)
    reset_points = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('penalty_reset_history', lazy=True))

    def __repr__(self):
        return f'<PenaltyResetHistory {self.id} for {self.user.username} on {self.reset_date}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'reset_date': self.reset_date.isoformat(),
            'reset_reason': self.reset_reason,
            'reset_points': self.reset_points,
            'timestamp': self.timestamp.isoformat(),
            'username': self.user.username if self.user else None
        }

class CommuteSchedule(db.Model): # 새로운 모델: 주간 출근시간표
    """
    주간 출근시간표 파일을 저장하는 모델입니다.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    week_start_date = db.Column(db.Date, nullable=False, unique=True) # 해당 주간의 시작일 (월요일)
    image_filename = db.Column(db.String(120), nullable=False) # 업로드된 시간표 파일명
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('commute_schedules', lazy=True))

    def __repr__(self):
        return f'<CommuteSchedule {self.id} for {self.user.username} - Week {self.week_start_date}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'week_start_date': self.week_start_date.isoformat(),
            'image_filename': self.image_filename,
            'timestamp': self.timestamp.isoformat(),
            'username': self.user.username if self.user else None
        }


# 데이터베이스 초기화 함수
def init_db():
    """
    애플리케이션 시작 시 데이터베이스 테이블을 생성하고,
    초기 사용자 (master, ddang)를 추가합니다.
    """
    with app.app_context():
        db.create_all() 

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
        # 'ddang' 사용자의 ID를 조회합니다.
        ddang_user = User.query.filter_by(username='ddang').first()
        ddang_user_id = ddang_user.id if ddang_user else None

        # ddang_user_id가 없으면 대시보드에 데이터가 없음을 표시할 수 있습니다.
        if not ddang_user_id:
            flash("댕댕님 계정을 찾을 수 없습니다. 데이터베이스 초기화를 확인해주세요.", 'error')
            return render_template('dashboard.html',
                                   reports=[], payments=[], cardio_logs=[], weight_entries=[],
                                   penalties=[], punishment_schedules=[], commute_schedules=[],
                                   ddang_total_penalty=0, ddang_pending_punishments=0, ddang_last_commute_auth="기록 없음",
                                   ddang_last_commute_schedule_upload="기록 없음")

        # 댕댕님 데이터만 조회하여 대시보드에 표시합니다.
        all_reports = CommuteAuthReport.query.filter_by(user_id=ddang_user_id).order_by(CommuteAuthReport.timestamp.desc()).limit(10).all()
        all_payments = Payment.query.filter_by(user_id=ddang_user_id).order_by(Payment.timestamp.desc()).limit(10).all()
        all_cardio_logs = Cardio.query.filter_by(user_id=ddang_user_id).order_by(Cardio.timestamp.desc()).limit(10).all()
        all_weight_entries = WeightEntry.query.filter_by(user_id=ddang_user_id).order_by(WeightEntry.timestamp.desc()).limit(10).all()
        all_penalties = Penalty.query.order_by(Penalty.timestamp.desc()).limit(10).all()
        all_punishment_schedules = PunishmentSchedule.query.filter_by(user_id=ddang_user_id).filter(
            PunishmentSchedule.status.in_(['pending', 'approved'])
        ).order_by(PunishmentSchedule.requested_datetime.asc()).limit(10).all()
        all_commute_schedules = CommuteSchedule.query.filter_by(user_id=ddang_user_id).order_by(CommuteSchedule.timestamp.desc()).limit(10).all() 

        # 댕댕님 요약 정보
        ddang_total_penalty = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=ddang_user_id).scalar() or 0
        ddang_pending_punishments = PunishmentSchedule.query.filter_by(user_id=ddang_user_id, status='pending').count()
        ddang_last_commute_auth_obj = CommuteAuthReport.query.filter_by(user_id=ddang_user_id).order_by(CommuteAuthReport.timestamp.desc()).first()
        ddang_last_commute_auth = ddang_last_commute_auth_obj.timestamp.strftime('%Y-%m-%d %H:%M') if ddang_last_commute_auth_obj else "기록 없음"
        ddang_last_commute_schedule_upload_obj = CommuteSchedule.query.filter_by(user_id=ddang_user_id).order_by(CommuteSchedule.timestamp.desc()).first()
        ddang_last_commute_schedule_upload = ddang_last_commute_schedule_upload_obj.timestamp.strftime('%Y-%m-%d %H:%M') if ddang_last_commute_schedule_upload_obj else "기록 없음"


        return render_template('dashboard.html',
                               reports=all_reports,
                               payments=all_payments,
                               cardio_logs=all_cardio_logs,
                               weight_entries=all_weight_entries,
                               penalties=all_penalties,
                               punishment_schedules=all_punishment_schedules,
                               commute_schedules=all_commute_schedules, 
                               ddang_total_penalty=ddang_total_penalty,
                               ddang_pending_punishments=ddang_pending_punishments,
                               ddang_last_commute_auth=ddang_last_commute_auth,
                               ddang_last_commute_schedule_upload=ddang_last_commute_schedule_upload) 
    else:
        user_id = session['user_id']
        total_penalty_points = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=user_id).scalar() or 0
        show_penalty_warning = (total_penalty_points > 0 and total_penalty_points % 5 == 0)

        return render_template('index.html', show_penalty_warning=show_penalty_warning) 

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    """
    'static/uploads' 폴더에 저장된 이미지 파일을 웹에서 접근할 수 있도록 제공합니다.
    """
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------------------------------------------
# 출근인증 (Commute Auth) 기능
# ---------------------------------------------------
@app.route('/commute_auth', methods=['GET', 'POST']) 
def commute_auth(): 
    """
    출근인증 제출 페이지를 처리하고, 제출 시 지각 여부에 따라 벌점을 부과합니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("출근인증을 제출할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    today = datetime.now().date()

    existing_commute_auth = CommuteAuthReport.query.filter( 
        CommuteAuthReport.user_id == user_id,
        func.date(CommuteAuthReport.timestamp) == today
    ).first()

    if request.method == 'POST':
        if existing_commute_auth:
            flash("오늘은 이미 출근인증을 제출하셨습니다.", 'warning')
            return redirect(url_for('commute_auth'))

        auth_content = request.form.get('commute_auth_content') 
        is_late_checkbox = request.form.get('is_late_checkbox') == 'on' 
        is_holiday_checkbox = request.form.get('is_holiday_checkbox') == 'on' # 휴무 체크박스 확인
        now = datetime.now()
        
        is_late_penalty = False
        
        if is_holiday_checkbox:
            # 휴무일로 기록, 벌점 없음
            new_commute_auth = CommuteAuthReport(
                user_id=user_id,
                content="휴무입니다.",
                timestamp=now,
                is_late=False,
                is_holiday=True # 휴무일로 저장
            )
            db.session.add(new_commute_auth)
            db.session.commit()
            flash("오늘은 휴무로 기록되었습니다.", 'info')
            return redirect(url_for('commute_auth'))

        # 휴무가 아닐 때만 지각 및 내용 검사
        if is_late_checkbox: 
            flash("지각을 선택하셨습니다. 지각 벌점이 부과됩니다.", 'warning')
            is_late_penalty = True
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type='출근인증 지각', 
                rule_name='출근인증',
                reason=f"출근인증 지각 선택: {now.strftime('%H:%M')}",
                penalty_points=1 
            )
            db.session.add(new_penalty)
        
        new_commute_auth = CommuteAuthReport( 
            user_id=user_id,
            content=auth_content,
            timestamp=now,
            is_late=is_late_penalty,
            is_holiday=False
        )
        db.session.add(new_commute_auth)
        db.session.commit()

        flash("출근인증이 성공적으로 제출되었습니다!", 'success')
        return redirect(url_for('commute_auth'))
    
    return render_template('commute_auth.html', 
                           existing_commute_auth=existing_commute_auth) 

@app.route('/commute_auth_history') 
def commute_auth_history(): 
    """
    현재 로그인한 사용자의 출근인증 이력을 조회합니다.
    """
    if 'user_id' not in session: # 로그인 여부 확인
        flash("이력을 조회할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    
    if session.get('role') == 'owner':
        # 관리자는 ddang 사용자의 이력을 조회
        ddang_user = User.query.filter_by(username='ddang').first()
        if ddang_user:
            user_reports = CommuteAuthReport.query.filter_by(user_id=ddang_user.id).order_by(CommuteAuthReport.timestamp.desc()).all()
        else:
            user_reports = [] # ddang 사용자가 없으면 빈 리스트
            flash("댕댕님 계정을 찾을 수 없습니다.", 'error')
    else: # 일반 사용자는 본인 이력을 조회
        user_reports = CommuteAuthReport.query.filter_by(user_id=user_id).order_by(CommuteAuthReport.timestamp.desc()).all() 
        
    return render_template('commute_auth_history.html', reports=user_reports) 

@app.route('/delete_commute_auth_selected', methods=['POST']) 
def delete_commute_auth_selected(): 
    """
    선택된 출근인증 기록을 삭제합니다.
    """
    if 'user_id' not in session: # 로그인 여부 확인
        flash("출근인증을 삭제할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    selected_report_ids = request.form.getlist('delete_ids') 
    
    # 관리자(owner)는 ddang의 기록을 삭제할 수 있도록 허용
    # 일반 사용자(sub)는 자신의 기록만 삭제할 수 있도록
    if session.get('role') == 'owner':
        # ddang 사용자의 ID를 조회
        ddang_user = User.query.filter_by(username='ddang').first()
        target_user_id = ddang_user.id if ddang_user else None
        if not target_user_id:
            flash("댕댕님 계정을 찾을 수 없습니다.", 'error')
            return redirect(url_for('commute_auth_history'))
    else: # sub 역할
        target_user_id = session['user_id']

    for report_id in selected_report_ids:
        report_to_delete = CommuteAuthReport.query.get(report_id) 
        # 삭제하려는 기록의 user_id가 현재 로그인한 사용자의 ID와 일치하거나,
        # 로그인한 사용자가 owner이고 target_user_id와 일치하는 경우에만 삭제 허용
        if report_to_delete and (report_to_delete.user_id == target_user_id or session.get('role') == 'owner'):
            db.session.delete(report_to_delete)
        else:
            flash(f"ID {report_id} 출근인증을 삭제할 권한이 없습니다.", 'error')
            db.session.rollback() # 오류 발생 시 롤백
            return redirect(url_for('commute_auth_history'))
    
    db.session.commit()
    flash("선택된 출근인증이 삭제되었습니다.", 'success')
    return redirect(url_for('commute_auth_history')) 

# ---------------------------------------------------
# 벌점 관리 기능
# ---------------------------------------------------
@app.route('/penalties')
def penalties():
    """
    사용자의 벌점 내역을 조회하고 총 벌점을 표시합니다.
    """
    print(f"DEBUG: Accessing /penalties. Session user_id: {session.get('user_id')}, role: {session.get('role')}")

    if 'user_id' not in session: 
        flash("벌점 내역을 조회할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if session.get('role') == 'owner':
        query = Penalty.query
    else: 
        query = Penalty.query.filter_by(user_id=user_id)
    
    filter_year = request.args.get('year', type=int)
    filter_month = request.args.get('month', type=int)
    filter_day = request.args.get('day', type=int)

    if filter_year:
        query = query.filter(extract('year', Penalty.timestamp) == filter_year)
    if filter_month:
        query = query.filter(extract('month', Penalty.timestamp) == filter_month)
    if filter_day:
        query = query.filter(extract('day', Penalty.timestamp) == filter_day)

    user_penalties = query.order_by(Penalty.timestamp.desc()).all()
    
    total_penalty_points = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=user_id).scalar() or 0

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
    주간 유산소 미달, 월간 소액결제 미달/초과 벌점을 부과하는 수동 트리거입니다.
    """
    print(f"DEBUG: Accessing /check_daily_weekly_penalties. Session user_id: {session.get('user_id')}, role: {session.get('role')}")

    if 'user_id' not in session:
        flash("벌점 확인 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    now = datetime.now()
    today = now.date()
    
    # --- 1. 출근인증 미제출 벌점 확인 (오늘 날짜 기준, 10시 이후에만) ---
    if now.hour >= 10:
        commute_auth_record_today = CommuteAuthReport.query.filter(
            CommuteAuthReport.user_id == user_id,
            func.date(CommuteAuthReport.timestamp) == today
        ).first()

        penalty_already_issued_today = Penalty.query.filter(
            Penalty.user_id == user_id,
            Penalty.penalty_type == '출근인증 미제출', 
            func.date(Penalty.timestamp) == today
        ).first()

        # 오늘 출근인증 기록이 없고, 오늘 벌점도 부과 안 됐고, 오늘이 휴무일도 아니라면
        if not commute_auth_record_today and not penalty_already_issued_today:
            # 휴무일 기록이 없는 경우에만 미제출 벌점 부과
            is_holiday_today_record = CommuteAuthReport.query.filter(
                CommuteAuthReport.user_id == user_id,
                func.date(CommuteAuthReport.timestamp) == today,
                CommuteAuthReport.is_holiday == True
            ).first()
            
            if not is_holiday_today_record: 
                new_penalty = Penalty(
                    user_id=user_id,
                    penalty_type='출근인증 미제출', 
                    rule_name='출근인증',
                    reason=f"오늘 출근인증 미제출 ({today.strftime('%Y-%m-%d')})",
                    penalty_points=2 
                )
                db.session.add(new_penalty)
                flash("오늘 출근인증 미제출로 벌점이 부과되었습니다.", 'warning')
    
    # --- 2. 지난 주 유산소 운동 벌점 확인 (일주일 후 3회 미만) ---
    last_week_end = today - timedelta(days=today.weekday() + 1) 
    last_week_start = last_week_end - timedelta(days=6) 

    penalty_for_last_week_cardio_issued = Penalty.query.filter(
        Penalty.user_id == user_id,
        Penalty.penalty_type.like('유산소 미달%'), 
        Penalty.related_date == last_week_start 
    ).first()

    if today.weekday() == 0 and not penalty_for_last_week_cardio_issued: 
        last_week_cardio_count = Cardio.query.filter(
            Cardio.user_id == user_id,
            Cardio.date >= last_week_start,
            Cardio.date <= last_week_end
        ).count()

        penalty_points = 0
        reason = ""
        if last_week_cardio_count < 3: 
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
                    related_date=last_week_start 
                )
                db.session.add(new_penalty)
                flash(f"지난주 유산소 운동 미달로 벌점 {penalty_points}점이 부과되었습니다.", 'warning')
    
    # --- 3. 소액결제 미달/초과 확인 (한달 후 50만원 이상이거나 미제출 시) ---
    if today.day == 1 and not Penalty.query.filter(
        Penalty.user_id == user_id,
        Penalty.penalty_type.like('소액결제 미달%'),
        extract('year', Penalty.related_date) == now.year,
        extract('month', Penalty.related_date) == now.month -1 if now.month > 1 else 12 
    ).first():
        
        prev_month_date = date(now.year, now.month, 1) - timedelta(days=1) 
        prev_month = prev_month_date.month
        prev_year = prev_month_date.year

        monthly_total_prev_month = db.session.query(func.sum(Payment.amount)).filter(
            Payment.user_id == user_id,
            extract('year', Payment.timestamp) == prev_year,
            extract('month', Payment.timestamp) == prev_month
        ).scalar() or 0
        limit = 500000 

        payments_exist_prev_month = Payment.query.filter(
            Payment.user_id == user_id,
            extract('year', Payment.timestamp) == prev_year,
            extract('month', Payment.timestamp) == prev_month
        ).first()

        if not payments_exist_prev_month: 
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type='소액결제 미제출',
                rule_name='소액결제',
                reason=f"지난달 소액결제 기록 미제출 ({prev_year}-{prev_month})",
                penalty_points=3, 
                related_date=date(prev_year, prev_month, 1) 
            )
            db.session.add(new_penalty)
            flash(f"지난달 소액결제 기록 미제출로 벌점 {new_penalty.penalty_points}점이 부과되었습니다.", 'warning')
        elif monthly_total_prev_month > limit: 
            new_penalty = Penalty(
                user_id=user_id,
                penalty_type='소액결제 미달 (한도 초과)',
                rule_name='소액결제',
                reason=f"지난달 소액결제 한도({limit:,.0f}원) 초과: {monthly_total_prev_month:,.0f}원",
                penalty_points=1, 
                related_date=date(prev_year, prev_month, 1) 
            )
            db.session.add(new_penalty)
            flash(f"지난달 소액결제 한도 초과로 벌점 {new_penalty.penalty_points}점이 부과되었습니다.", 'warning')
    
    # --- 4. 체중 증가 벌점 확인 (1주 월~일, 2주 월~일 기준으로 다음 몸무게 보고일 언제 체중 1키로 증가하면 벌점 1점) ---
    current_week_start = today - timedelta(days=today.weekday())
    last_week_start_for_weight = current_week_start - timedelta(days=7)
    week_before_last_start_for_weight = current_week_start - timedelta(days=14)

    if today.weekday() == 0 and not Penalty.query.filter(
        Penalty.user_id == user_id,
        Penalty.penalty_type == '체중 증가',
        Penalty.related_date == last_week_start_for_weight 
    ).first():
        
        last_weight_last_week = WeightEntry.query.filter(
            WeightEntry.user_id == user_id,
            func.date(WeightEntry.timestamp) >= last_week_start_for_weight,
            func.date(WeightEntry.timestamp) < current_week_start 
        ).order_by(WeightEntry.timestamp.desc()).first()

        last_weight_week_before_last = WeightEntry.query.filter(
            WeightEntry.user_id == user_id,
            func.date(WeightEntry.timestamp) >= week_before_last_start_for_weight,
            func.date(WeightEntry.timestamp) < last_week_start_for_weight 
        ).order_by(WeightEntry.timestamp.desc()).first()

        if last_weight_last_week and last_weight_week_before_last:
            weight_change = last_weight_last_week.weight_kg - last_weight_week_before_last.weight_kg
            
            if weight_change > 1.0: 
                new_penalty = Penalty(
                    user_id=user_id,
                    penalty_type='체중 증가',
                    rule_name='체중 관리',
                    reason=f"지난 2주간 체중 {weight_change:.1f}kg 증가 (1kg 초과)",
                    penalty_points=1, 
                    related_date=last_week_start_for_weight 
                )
                db.session.add(new_penalty)
                flash(f"경고: 지난 2주간 체중이 1kg 이상 증가하여 벌점 {new_penalty.penalty_points}점이 부과되었습니다!", 'warning')
        elif last_weight_last_week and not last_weight_week_before_last:
            pass 

    db.session.commit() 
    flash("벌점 확인이 완료되었습니다.", 'info')
    return redirect(url_for('penalties'))

# ---------------------------------------------------
# 출근시간표 업로드 기능 (새롭게 추가)
# ---------------------------------------------------
@app.route('/upload_commute_schedule', methods=['GET', 'POST'])
def upload_commute_schedule():
    """
    주간 출근시간표 파일을 업로드하는 페이지입니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("출근시간표를 업로드할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']

    if request.method == 'POST':
        schedule_file = request.files.get('schedule_file')
        week_start_date_str = request.form.get('week_start_date')

        try:
            week_start_date = datetime.strptime(week_start_date_str, '%Y-%m-%d').date()
            # 입력된 날짜가 월요일인지 확인
            if week_start_date.weekday() != 0: # 월요일이 아니면 (월요일=0)
                flash("주간 시작일은 월요일이어야 합니다.", 'error')
                return redirect(url_for('upload_commute_schedule'))
        except ValueError:
            flash("유효한 날짜 형식을 입력해주세요 (YYYY-MM-%d).", 'error')
            return redirect(url_for('upload_commute_schedule'))

        if not schedule_file:
            flash("시간표 파일은 필수입니다.", 'error')
            return redirect(url_for('upload_commute_schedule'))
        
        # 파일 확장자 확인
        if not allowed_file(schedule_file.filename):
            flash("허용되지 않는 파일 형식입니다. (png, jpg, jpeg, gif, pdf만 가능)", 'warning')
            return redirect(url_for('upload_commute_schedule'))

        # 파일 저장
        filename = secure_filename(schedule_file.filename)
        unique_filename = f"schedule_{week_start_date.strftime('%Y%m%d')}_{filename}"
        schedule_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))

        # DB에 기록
        new_schedule = CommuteSchedule(
            user_id=user_id,
            week_start_date=week_start_date,
            image_filename=unique_filename
        )
        db.session.add(new_schedule)
        db.session.commit()
        flash("주간 출근시간표가 성공적으로 업로드되었습니다!", 'success')
        return redirect(url_for('upload_commute_schedule'))

    # 기존 출근시간표 기록 조회
    user_commute_schedules = CommuteSchedule.query.filter_by(user_id=user_id).order_by(CommuteSchedule.timestamp.desc()).all()

    return render_template('upload_commute_schedule.html', schedules=user_commute_schedules)

# ---------------------------------------------------
# 반성문 / 교육 요청 기능 (사용자 요청에 따라 제거)
# ---------------------------------------------------
# @app.route('/reflection_submission', methods=['GET', 'POST'])
# def reflection_submission():
#     pass 

# @app.route('/reflection_history_list')
# def reflection_history_list():
#     pass 

@app.route('/calendar_view') # 캘린더 뷰 라우트
def calendar_view():
    """
    캘린더 뷰를 제공하고, 모든 기록 데이터를 JSON 형태로 전달합니다.
    """
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if session.get('role') == 'owner':
        reports_raw = CommuteAuthReport.query.order_by(CommuteAuthReport.timestamp.desc()).all() 
        penalties_raw = Penalty.query.order_by(Penalty.timestamp.desc()).all()
        punishment_schedules_raw = PunishmentSchedule.query.order_by(PunishmentSchedule.timestamp.desc()).all()
        penalty_reset_history_raw = PenaltyResetHistory.query.order_by(PenaltyResetHistory.timestamp.desc()).all()
        commute_schedules_raw = CommuteSchedule.query.order_by(CommuteSchedule.timestamp.desc()).all() 
    else: 
        reports_raw = CommuteAuthReport.query.filter_by(user_id=user_id).order_by(CommuteAuthReport.timestamp.desc()).all() 
        penalties_raw = Penalty.query.filter_by(user_id=user_id).order_by(Penalty.timestamp.desc()).all()
        punishment_schedules_raw = PunishmentSchedule.query.filter_by(user_id=user_id).order_by(PunishmentSchedule.timestamp.desc()).all()
        penalty_reset_history_raw = PenaltyResetHistory.query.filter_by(user_id=user_id).order_by(PenaltyResetHistory.timestamp.desc()).all()
        commute_schedules_raw = CommuteSchedule.query.filter_by(user_id=user_id).order_by(CommuteSchedule.timestamp.desc()).all() 

    reports_json = [r.to_dict() for r in reports_raw]
    penalties_json = [p.to_dict() for p in penalties_raw]
    punishment_schedules_json = [s.to_dict() for s in punishment_schedules_raw]
    penalty_reset_history_json = [pr.to_dict() for pr in penalty_reset_history_raw]
    commute_schedules_json = [cs.to_dict() for cs in commute_schedules_raw] 

    return render_template('calendar.html',
                           reports=reports_json,
                           penalties=penalties_json,
                           punishment_schedules=punishment_schedules_json,
                           penalty_reset_history=penalty_reset_history_json,
                           commute_schedules=commute_schedules_json) 

# ---------------------------------------------------
# 체벌 일정 관리 기능
# ---------------------------------------------------
@app.route('/request_punishment', methods=['GET', 'POST'])
def request_punishment():
    """
    댕댕님이 체벌/교육 일정을 요청하는 페이지입니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("일정 요청 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        requested_datetime_str = request.form.get('requested_datetime')
        reason = request.form.get('reason')
        requested_tool = request.form.get('requested_tool')

        try:
            requested_datetime = datetime.strptime(requested_datetime_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("유효한 날짜 및 시간을 입력해주세요.", 'error')
            return redirect(url_for('request_punishment'))
        
        if not reason:
            flash("요청 사유는 필수입니다.", 'error')
            return redirect(url_for('request_punishment'))

        new_request = PunishmentSchedule(
            user_id=session['user_id'],
            requested_datetime=requested_datetime,
            reason=reason,
            requested_tool=requested_tool,
            status='pending'
        )
        db.session.add(new_request)
        db.session.commit()
        flash("체벌/교육 일정이 성공적으로 요청되었습니다.", 'success')
        return redirect(url_for('home'))

    spanking_tools = ['손바닥', '패들', '벨트', '회초리', '기타']
    return render_template('request_punishment.html', spanking_tools=spanking_tools)


@app.route('/admin_punishment_requests')
def admin_punishment_requests():
    """
    관리자가 체벌/교육 요청을 확인하고 승인/거절하는 페이지입니다.
    """
    if 'user_id' not in session or session.get('role') != 'owner':
        flash("관리자 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    pending_requests = PunishmentSchedule.query.filter_by(status='pending').order_by(PunishmentSchedule.timestamp.asc()).all()
    all_schedules = PunishmentSchedule.query.order_by(PunishmentSchedule.timestamp.desc()).all()

    return render_template('admin_punishment_requests.html', 
                           pending_requests=pending_requests,
                           all_schedules=all_schedules)

@app.route('/approve_punishment/<int:schedule_id>', methods=['POST'])
def approve_punishment(schedule_id):
    """
    관리자가 체벌/교육 요청을 승인합니다.
    """
    if 'user_id' not in session or session.get('role') != 'owner':
        flash("관리자 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    schedule = PunishmentSchedule.query.get_or_404(schedule_id)
    if schedule.status == 'pending':
        schedule.status = 'approved'
        schedule.approved_datetime = datetime.now()
        db.session.commit()
        flash("체벌/교육 요청이 승인되었습니다.", 'success')
    else:
        flash("이미 처리된 요청입니다.", 'warning')
    return redirect(url_for('admin_punishment_requests'))

@app.route('/reject_punishment/<int:schedule_id>', methods=['POST'])
def reject_punishment(schedule_id):
    """
    관리자가 체벌/교육 요청을 거절합니다.
    """
    if 'user_id' not in session or session.get('role') != 'owner':
        flash("관리자 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    schedule = PunishmentSchedule.query.get_or_404(schedule_id)
    if schedule.status == 'pending':
        schedule.status = 'rejected'
        db.session.commit()
        flash("체벌/교육 요청이 거절되었습니다.", 'info')
    else:
        flash("이미 처리된 요청입니다.", 'warning')
    return redirect(url_for('admin_punishment_requests'))

@app.route('/complete_punishment/<int:schedule_id>', methods=['POST'])
def complete_punishment(schedule_id):
    """
    관리자가 체벌/교육 일정을 완료 처리하고 벌점을 리셋합니다.
    """
    if 'user_id' not in session or session.get('role') != 'owner':
        flash("관리자 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    schedule = PunishmentSchedule.query.get_or_404(schedule_id)
    if schedule.status == 'approved':
        schedule.status = 'completed'
        
        # 벌점 리셋
        user_id = schedule.user_id
        total_penalty_before_reset = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=user_id).scalar() or 0
        
        # 해당 사용자의 모든 벌점 기록 삭제
        Penalty.query.filter_by(user_id=user_id).delete()
        
        # 벌점 리셋 이력 저장
        new_reset_history = PenaltyResetHistory(
            user_id=user_id,
            reset_date=date.today(),
            reset_reason=f"체벌/교육 완료 (일정 ID: {schedule.id})",
            reset_points=total_penalty_before_reset
        )
        db.session.add(new_reset_history)

        db.session.commit()
        flash(f"체벌/교육이 완료되었고, {schedule.user.username}님의 벌점 {total_penalty_before_reset}점이 리셋되었습니다.", 'success')
    else:
        flash("승인된 일정이 아니거나 이미 완료되었습니다.", 'warning')
    return redirect(url_for('admin_punishment_requests'))

@app.route('/request_reschedule/<int:schedule_id>', methods=['GET', 'POST'])
def request_reschedule(schedule_id):
    """
    댕댕님이 체벌 일정을 연기 요청하는 페이지입니다.
    """
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("일정 연기 요청 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    
    schedule = PunishmentSchedule.query.get_or_404(schedule_id)
    
    if schedule.user_id != session['user_id']:
        flash("본인의 일정만 연기 요청할 수 있습니다.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        reschedule_reason = request.form.get('reschedule_reason')
        new_requested_datetime_str = request.form.get('new_requested_datetime')

        if not reschedule_reason:
            flash("연기 사유는 필수입니다.", 'error')
            return redirect(url_for('request_reschedule', schedule_id=schedule_id))
        
        try:
            new_requested_datetime = datetime.strptime(new_requested_datetime_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("유효한 새로운 날짜 및 시간을 입력해주세요.", 'error')
            return redirect(url_for('request_reschedule', schedule_id=schedule_id))

        # 기존 요청 상태를 'rescheduled'로 변경하고 새로운 요청으로 기록
        schedule.status = 'rescheduled'
        schedule.admin_notes = f"연기 요청됨: {reschedule_reason}" # 기존 요청에 메모 추가
        
        # 새로운 요청 생성 (관리자가 승인해야 최종 반영)
        new_request = PunishmentSchedule(
            user_id=session['user_id'],
            requested_datetime=new_requested_datetime,
            reason=f"일정 연기 요청 (기존 ID: {schedule.id}): {reschedule_reason}",
            requested_tool=schedule.requested_tool,
            status='pending' # 연기 요청은 다시 'pending' 상태로
        )
        db.session.add(new_request)
        db.session.commit()
        flash("일정 연기 요청이 성공적으로 제출되었습니다. 관리자의 승인을 기다려주세요.", 'success')
        return redirect(url_for('home'))

    return render_template('request_reschedule.html', schedule=schedule)


# ---------------------------------------------------
# 소액결제 관리 (명세서 사진 필수 추가)
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
        image_file = request.files.get('image') # 명세서 사진 추가

        if not amount or amount <= 0:
            flash("유효한 금액을 입력해주세요.", 'error')
            return redirect(url_for('payments'))

        image_filename = save_uploaded_file(image_file) 
        if not image_filename: # 명세서 사진 필수
            flash("명세서 사진은 필수이며, 허용되는 파일 형식(png, jpg, jpeg, gif)이어야 합니다.", 'error')
            return redirect(url_for('payments'))

        new_payment = Payment(user_id=user_id, amount=amount, description=description, image_filename=image_filename)
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
                extract('year', Payment.timestamp) == current_year,
                extract('month', Payment.timestamp) == current_month
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

# BookReview 모델 제거
# @app.route('/book_reviews', methods=['GET', 'POST'])
# def book_reviews():
#     pass

@app.route('/cardio', methods=['GET', 'POST'])
def cardio():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']

    if request.method == 'POST':
        cardio_date_str = request.form.get('cardio_date')
        image_file = request.files.get('image') # 사진 파일

        try:
            cardio_date = datetime.strptime(cardio_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("유효한 날짜 형식을 입력해주세요 (YYYY-MM-DD).", 'error')
            return redirect(url_for('cardio'))

        image_filename = save_uploaded_file(image_file) 
        if not image_filename: # 유산소 사진 필수
            flash("인증 사진은 필수이며, 허용되는 파일 형식(png, jpg, jpeg, gif)이어야 합니다.", 'error')
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
    ).order_by(db.desc(Cardio.timestamp)).all() # 올바르게 수정된 부분

    weekly_count = len(weekly_cardio_logs)
    
    recent_logs = Cardio.query.filter_by(user_id=user_id).order_by(db.desc(Cardio.timestamp)).limit(7).all() # 올바르게 수정된 부분

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

        # 2주간 1kg 이상 증가 시 벌점 로직은 check_daily_weekly_penalties로 이동
        return redirect(url_for('weight'))

    today = datetime.now().date()
    start_of_week = today - timedelta(days=today.weekday()) 
    end_of_week = start_of_week + timedelta(days=6)

    user_weight_entries = WeightEntry.query.filter_by(user_id=user_id).order_by(db.desc(WeightEntry.timestamp)).all() # 올바르게 수정된 부분
    
    labels = [entry.timestamp.strftime('%m-%d') for entry in user_weight_entries]
    data = [entry.weight_kg for entry in user_weight_entries]
    
    warning_message = None
    if len(user_weight_entries) >= 2:
        two_weeks_ago = datetime.now() - timedelta(weeks=2)
        recent_entries = WeightEntry.query.filter(
            WeightEntry.user_id == user_id,
            func.date(WeightEntry.timestamp) >= two_weeks_ago.date() 
        ).order_by(db.desc(WeightEntry.timestamp)).all() # 올바르게 수정된 부분
        
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

# MealLog 모델 제거
# @app.route('/meal_logs', methods=['GET', 'POST'])
# def meal_logs():
#     pass


# 애플리케이션 실행 진입점
if __name__ == '__main__':
    init_db()
    # 프로덕션 환경에서는 debug=False로 설정해야 합니다.
    # app.run(debug=True, host='0.0.0.0', port=5000) 
    # Gunicorn과 Systemd를 통해 실행되므로 이 부분은 주석 처리합니다.


