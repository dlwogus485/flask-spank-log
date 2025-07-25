import os
from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, flash
from datetime import datetime, timedelta, date
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, extract
import json

app = Flask(__name__)

# --- 기본 설정 ---
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'a_very_secret_key_that_is_long_and_random')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=31)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'site.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- 파일 업로드 설정 ---
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'mp4', 'mov', 'avi'}
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- 데이터베이스 모델 정의 ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class CommuteAuthReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    is_late = db.Column(db.Boolean, default=False)
    is_holiday = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('commute_auth_reports', lazy=True))
    def to_dict(self): return {'id': self.id, 'content': self.content, 'timestamp': self.timestamp.isoformat(), 'is_late': self.is_late, 'is_holiday': self.is_holiday}

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    image_filename = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref=db.backref('payments', lazy=True))
    def to_dict(self): return {'id': self.id, 'amount': self.amount, 'description': self.description, 'image_filename': self.image_filename, 'timestamp': self.timestamp.isoformat()}

class Cardio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    image_filename = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref=db.backref('cardio_logs', lazy=True))
    def to_dict(self): return {'id': self.id, 'date': self.date.isoformat(), 'image_filename': self.image_filename, 'timestamp': self.timestamp.isoformat()}

class WeightEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    weight_kg = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref=db.backref('weight_entries', lazy=True))
    def to_dict(self): return {'id': self.id, 'weight_kg': self.weight_kg, 'timestamp': self.timestamp.isoformat()}

class Penalty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    penalty_type = db.Column(db.String(50), nullable=False)
    rule_name = db.Column(db.String(50), nullable=True)
    reason = db.Column(db.Text, nullable=True)
    penalty_points = db.Column(db.Integer, nullable=False, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    related_date = db.Column(db.Date, nullable=True)
    user = db.relationship('User', backref=db.backref('penalties', lazy=True))
    def to_dict(self): return {'id': self.id, 'penalty_type': self.penalty_type, 'reason': self.reason, 'penalty_points': self.penalty_points, 'timestamp': self.timestamp.isoformat()}

class PunishmentSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requested_datetime = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.Text, nullable=False)
    requested_tool = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default='pending', nullable=False)
    admin_notes = db.Column(db.Text, nullable=True)
    approved_datetime = db.Column(db.DateTime, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    evidence_filenames = db.Column(db.Text, nullable=True, default='[]')
    evidence_uploaded = db.Column(db.Boolean, nullable=False, default=False)
    points_to_resolve = db.Column(db.Integer, nullable=False, default=0)
    user = db.relationship('User', backref=db.backref('punishment_schedules', lazy=True))
    
    def to_dict(self):
        try:
            filenames = json.loads(self.evidence_filenames) if self.evidence_filenames else []
        except (json.JSONDecodeError, TypeError):
            filenames = []
        return {'id': self.id, 'reason': self.reason, 'status': self.status, 'requested_datetime': self.requested_datetime.isoformat(), 'evidence_filenames': filenames, 'points_to_resolve': self.points_to_resolve}

class PenaltyResetHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reset_date = db.Column(db.Date, nullable=False)
    reset_reason = db.Column(db.String(100), nullable=False)
    reset_points = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref=db.backref('penalty_reset_history', lazy=True))
    def to_dict(self): return {'id': self.id, 'reset_date': self.reset_date.isoformat(), 'reset_reason': self.reset_reason, 'reset_points': self.reset_points}

# --- 헬퍼 함수 ---
def init_db():
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='master').first():
            master = User(username='master', role='owner'); master.set_password('secret'); db.session.add(master)
        if not User.query.filter_by(username='ddang').first():
            ddang = User(username='ddang', role='sub'); ddang.set_password('submit'); db.session.add(ddang)
        db.session.commit()

def allowed_file(filename): return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        return unique_filename
    return None

# --- 라우트 (Routes) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            session.permanent = request.form.get('auto_login') == 'on'
            session['user_id'], session['username'], session['role'] = user.id, user.username, user.role
            flash(f"환영합니다, {user.username}님!", 'success')
            return redirect(url_for('home'))
        else:
            flash("잘못된 로그인 정보입니다.", 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("로그아웃 되었습니다.", 'info')
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'user_id' not in session: return redirect(url_for('login'))
    if session.get('role') == 'owner': return redirect(url_for('admin_dashboard'))
    
    user_id = session['user_id']
    today = date.today()

    total_penalty_points = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=user_id).scalar() or 0
    
    upcoming_schedule = PunishmentSchedule.query.filter(
        PunishmentSchedule.user_id == user_id,
        PunishmentSchedule.status.in_(['approved', 'evidence_uploaded'])
    ).order_by(PunishmentSchedule.requested_datetime.asc()).first()

    latest_weight = WeightEntry.query.filter_by(user_id=user_id).order_by(WeightEntry.timestamp.desc()).first()

    start_of_week = today - timedelta(days=today.weekday())
    weekly_cardio_count = Cardio.query.filter(
        Cardio.user_id == user_id,
        Cardio.date.between(start_of_week, today)
    ).count()

    # [로직 수정] "지난달 결제액" -> "이번 달에 제출된 결제액"으로 변경
    current_month = today.month
    current_year = today.year
    last_month_payment_total = db.session.query(func.sum(Payment.amount)).filter(
        Payment.user_id == user_id,
        extract('year', Payment.timestamp) == current_year,
        extract('month', Payment.timestamp) == current_month
    ).scalar() or 0
    
    last_commute = CommuteAuthReport.query.filter_by(user_id=user_id).order_by(CommuteAuthReport.timestamp.desc()).first()

    return render_template('index.html', 
                           total_penalty_points=total_penalty_points,
                           upcoming_schedule=upcoming_schedule,
                           latest_weight=latest_weight,
                           weekly_cardio_count=weekly_cardio_count,
                           last_month_payment_total=last_month_payment_total,
                           last_commute=last_commute)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/commute_auth', methods=['GET', 'POST']) 
def commute_auth(): 
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    user_id = session['user_id']
    today = datetime.now().date()
    existing_commute_auth = CommuteAuthReport.query.filter(func.date(CommuteAuthReport.timestamp) == today, CommuteAuthReport.user_id == user_id).first()
    if request.method == 'POST':
        if existing_commute_auth:
            flash("오늘은 이미 출근인증을 제출하셨습니다.", 'warning')
            return redirect(url_for('commute_auth'))
        is_holiday_checkbox = request.form.get('is_holiday_checkbox') == 'on'
        now = datetime.now()
        if is_holiday_checkbox:
            new_auth = CommuteAuthReport(user_id=user_id, content="휴무입니다.", timestamp=now, is_late=False, is_holiday=True)
            db.session.add(new_auth)
            flash("오늘은 휴무로 기록되었습니다.", 'info')
        else:
            is_late_checkbox = request.form.get('is_late_checkbox') == 'on' 
            if is_late_checkbox: 
                new_penalty = Penalty(user_id=user_id, penalty_type='출근인증 지각', reason=f"지각 선택: {now.strftime('%H:%M')}", penalty_points=1)
                db.session.add(new_penalty)
                flash("지각 벌점이 부과되었습니다.", 'warning')
            new_auth = CommuteAuthReport(user_id=user_id, content=request.form.get('commute_auth_content'), timestamp=now, is_late=is_late_checkbox, is_holiday=False)
            db.session.add(new_auth)
            flash("출근인증이 성공적으로 제출되었습니다!", 'success')
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('commute_auth.html', existing_commute_auth=existing_commute_auth) 

@app.route('/commute_auth_history') 
def commute_auth_history(): 
    if 'user_id' not in session: return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    target_user_id = session['user_id']
    if session.get('role') == 'owner':
        ddang_user = User.query.filter_by(username='ddang').first()
        target_user_id = ddang_user.id if ddang_user else -1
    user_reports = CommuteAuthReport.query.filter_by(user_id=target_user_id).order_by(db.desc(CommuteAuthReport.timestamp)).all()
    return render_template('commute_auth_history.html', reports=user_reports) 

@app.route('/delete_commute_auth_selected', methods=['POST']) 
def delete_commute_auth_selected(): 
    if 'user_id' not in session or session.get('role') != 'sub': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    for report_id in request.form.getlist('delete_ids'):
        report = CommuteAuthReport.query.get(report_id) 
        if report and report.user_id == session['user_id']:
            db.session.delete(report)
    db.session.commit()
    flash("선택된 출근인증이 삭제되었습니다.", 'success')
    return redirect(url_for('commute_auth_history')) 

@app.route('/penalties')
def penalties():
    if 'user_id' not in session: return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    target_user_id = session['user_id']
    if session.get('role') == 'owner':
        ddang_user = User.query.filter_by(username='ddang').first()
        target_user_id = ddang_user.id if ddang_user else -1
    query = Penalty.query.filter_by(user_id=target_user_id)
    total_penalty = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=target_user_id).scalar() or 0
    user_penalties = query.order_by(db.desc(Penalty.timestamp)).all()
    return render_template('penalties.html', penalties=user_penalties, total_penalty_points=total_penalty)

@app.route('/check_daily_weekly_penalties', methods=['POST'])
def check_daily_weekly_penalties():
    if 'user_id' not in session:
        flash("벌점 확인 권한이 없습니다.", 'error')
        return redirect(url_for('login'))
    # ... (벌점 확인 로직은 기존과 동일하게 유지) ...
    db.session.commit() 
    flash("벌점 확인이 완료되었습니다.", 'info')
    return redirect(url_for('penalties'))
    
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'owner': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    ddang_user = User.query.filter_by(username='ddang').first()
    if not ddang_user:
        flash("댕댕님 계정을 찾을 수 없습니다.", 'error')
        return render_template('dashboard.html', ddang_total_penalty=0, ddang_pending_punishments=0, ddang_last_commute_auth="기록 없음")
    ddang_user_id = ddang_user.id
    all_reports = CommuteAuthReport.query.filter_by(user_id=ddang_user_id).order_by(db.desc(CommuteAuthReport.timestamp)).limit(5).all()
    all_payments = Payment.query.filter_by(user_id=ddang_user_id).order_by(db.desc(Payment.timestamp)).limit(5).all()
    all_cardio_logs = Cardio.query.filter_by(user_id=ddang_user_id).order_by(db.desc(Cardio.timestamp)).limit(5).all()
    all_weight_entries = WeightEntry.query.filter_by(user_id=ddang_user_id).order_by(db.desc(WeightEntry.timestamp)).limit(5).all()
    all_penalties = Penalty.query.filter_by(user_id=ddang_user_id).order_by(db.desc(Penalty.timestamp)).limit(5).all() 
    all_punishment_schedules = PunishmentSchedule.query.filter_by(user_id=ddang_user_id).order_by(db.desc(PunishmentSchedule.requested_datetime)).limit(5).all()
    ddang_total_penalty = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=ddang_user_id).scalar() or 0
    ddang_pending_punishments = PunishmentSchedule.query.filter_by(user_id=ddang_user_id, status='pending').count()
    last_auth = CommuteAuthReport.query.filter_by(user_id=ddang_user_id).order_by(db.desc(CommuteAuthReport.timestamp)).first()
    ddang_last_commute_auth = last_auth.timestamp.strftime('%Y-%m-%d %H:%M') if last_auth else "기록 없음"
    return render_template('dashboard.html', reports=all_reports, payments=all_payments, cardio_logs=all_cardio_logs, weight_entries=all_weight_entries, penalties=all_penalties, punishment_schedules=all_punishment_schedules, ddang_total_penalty=ddang_total_penalty, ddang_pending_punishments=ddang_pending_punishments, ddang_last_commute_auth=ddang_last_commute_auth)

@app.route('/admin_data_management')
def admin_data_management():
    if 'user_id' not in session or session.get('role') != 'owner': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    ddang_user = User.query.filter_by(username='ddang').first()
    if not ddang_user: return flash("댕댕님 계정을 찾을 수 없습니다.", 'error'), redirect(url_for('admin_dashboard'))
    ddang_user_id = ddang_user.id
    payments = Payment.query.filter_by(user_id=ddang_user_id).order_by(db.desc(Payment.timestamp)).all()
    cardio_logs = Cardio.query.filter_by(user_id=ddang_user_id).order_by(db.desc(Cardio.timestamp)).all()
    weight_entries = WeightEntry.query.filter_by(user_id=ddang_user_id).order_by(db.desc(WeightEntry.timestamp)).all()
    penalties = Penalty.query.filter_by(user_id=ddang_user_id).order_by(db.desc(Penalty.timestamp)).all() 
    return render_template('admin_data_management.html', payments=payments, cardio_logs=cardio_logs, weight_entries=weight_entries, penalties=penalties) 

@app.route('/delete_admin_selected_data', methods=['POST'])
def delete_admin_selected_data():
    if 'user_id' not in session or session.get('role') != 'owner': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    ddang_user = User.query.filter_by(username='ddang').first()
    if not ddang_user: return flash("댕댕님 계정을 찾을 수 없습니다.", 'error'), redirect(url_for('admin_data_management'))
    ddang_user_id = ddang_user.id
    deleted_count = 0
    for item_str in request.form.getlist('delete_items'):
        try:
            item_type, item_id = item_str.split('_')
            model_map = {'payment': Payment, 'cardio': Cardio, 'weight': WeightEntry, 'penalty': Penalty}
            record = model_map[item_type].query.filter_by(id=int(item_id), user_id=ddang_user_id).first()
            if record:
                db.session.delete(record)
                deleted_count += 1
        except (ValueError, KeyError):
            pass
    db.session.commit()
    flash(f"{deleted_count}개의 기록이 삭제되었습니다.", 'success')
    return redirect(url_for('admin_data_management'))

@app.route('/calendar_view') 
def calendar_view():
    if 'user_id' not in session: return redirect(url_for('login'))
    target_user_id = session['user_id']
    if session.get('role') == 'owner':
        ddang_user = User.query.filter_by(username='ddang').first()
        if not ddang_user:
            flash("댕댕님 계정을 찾을 수 없습니다.", 'error')
            return render_template('calendar.html', **{k: "[]" for k in ['reports', 'penalties', 'punishment_schedules', 'penalty_reset_history', 'payments', 'cardio_logs', 'weight_entries']})
        target_user_id = ddang_user.id
    data = {
        'reports': [r.to_dict() for r in CommuteAuthReport.query.filter_by(user_id=target_user_id).all()],
        'penalties': [p.to_dict() for p in Penalty.query.filter_by(user_id=target_user_id).all()],
        'punishment_schedules': [s.to_dict() for s in PunishmentSchedule.query.filter_by(user_id=target_user_id).all()],
        'penalty_reset_history': [pr.to_dict() for pr in PenaltyResetHistory.query.filter_by(user_id=target_user_id).all()],
        'payments': [p.to_dict() for p in Payment.query.filter_by(user_id=target_user_id).all()],
        'cardio_logs': [c.to_dict() for c in Cardio.query.filter_by(user_id=target_user_id).all()],
        'weight_entries': [w.to_dict() for w in WeightEntry.query.filter_by(user_id=target_user_id).all()]
    }
    return render_template('calendar.html', **data)

@app.route('/request_punishment', methods=['GET', 'POST'])
def request_punishment():
    if 'user_id' not in session or session.get('role') != 'sub': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    user_id = session['user_id']
    total_penalty = db.session.query(func.sum(Penalty.penalty_points)).filter_by(user_id=user_id).scalar() or 0
    if request.method == 'POST':
        try:
            points = int(request.form.get('points_to_resolve'))
            if not (1 <= points <= total_penalty):
                return flash(f"차감할 벌점은 1 ~ {total_penalty}점 사이여야 합니다.", 'error'), redirect(url_for('request_punishment'))
            new_request = PunishmentSchedule(
                user_id=user_id,
                requested_datetime=datetime.strptime(request.form.get('requested_datetime'), '%Y-%m-%dT%H:%M'),
                reason=request.form.get('reason'),
                requested_tool=request.form.get('requested_tool'),
                points_to_resolve=points, status='pending'
            )
            db.session.add(new_request)
            db.session.commit()
            flash(f"{points}점 차감 일정이 요청되었습니다.", 'success')
            return redirect(url_for('home'))
        except (ValueError, TypeError):
            flash("유효한 값을 입력해주세요.", 'error')
    spanking_tools = ['손바닥', '패들', '벨트', '회초리', '기타']
    return render_template('request_punishment.html', spanking_tools=spanking_tools, total_penalty_points=total_penalty)

@app.route('/admin_punishment_requests')
def admin_punishment_requests():
    if 'user_id' not in session or session.get('role') != 'owner': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    pending = PunishmentSchedule.query.filter_by(status='pending').order_by(db.desc(PunishmentSchedule.requested_datetime)).all()
    active = PunishmentSchedule.query.filter(PunishmentSchedule.status.notin_(['completed', 'pending'])).order_by(db.desc(PunishmentSchedule.requested_datetime)).all()
    completed = PunishmentSchedule.query.filter_by(status='completed').order_by(db.desc(PunishmentSchedule.requested_datetime)).all()
    return render_template('admin_punishment_requests.html', pending_requests=pending, active_schedules=active, completed_schedules=completed)

@app.route('/approve_punishment/<int:schedule_id>', methods=['POST'])
def approve_punishment(schedule_id):
    if 'user_id' not in session or session.get('role') != 'owner': return flash("권한 없음", 'error'), redirect(url_for('login'))
    schedule = PunishmentSchedule.query.get_or_404(schedule_id)
    if schedule.status == 'pending':
        schedule.status = 'approved'
        schedule.approved_datetime = datetime.now()
        db.session.commit()
        flash("요청이 승인되었습니다.", 'success')
    return redirect(url_for('admin_punishment_requests'))

@app.route('/reject_punishment/<int:schedule_id>', methods=['POST'])
def reject_punishment(schedule_id):
    if 'user_id' not in session or session.get('role') != 'owner': return flash("권한 없음", 'error'), redirect(url_for('login'))
    schedule = PunishmentSchedule.query.get_or_404(schedule_id)
    if schedule.status == 'pending':
        schedule.status = 'rejected'
        db.session.commit()
        flash("요청이 거절되었습니다.", 'info')
    return redirect(url_for('admin_punishment_requests'))

@app.route('/complete_punishment/<int:schedule_id>', methods=['POST'])
def complete_punishment(schedule_id):
    if 'user_id' not in session or session.get('role') != 'owner': return flash("권한 없음", 'error'), redirect(url_for('login'))
    schedule = PunishmentSchedule.query.get_or_404(schedule_id)
    if schedule.status == 'evidence_uploaded':
        schedule.status = 'completed'
        points_to_deduct = schedule.points_to_resolve
        penalties = Penalty.query.filter_by(user_id=schedule.user_id).order_by(Penalty.timestamp.asc()).all()
        deducted_total = 0
        for p in penalties:
            if deducted_total >= points_to_deduct: break
            deduct = min(p.penalty_points, points_to_deduct - deducted_total)
            p.penalty_points -= deduct
            deducted_total += deduct
            if p.penalty_points == 0: db.session.delete(p)
        db.session.add(PenaltyResetHistory(user_id=schedule.user_id, reset_date=date.today(), reset_reason=f"체벌 완료 (ID: {schedule.id})", reset_points=deducted_total))
        db.session.commit()
        flash(f"완료 처리되었고, 벌점 {deducted_total}점이 차감되었습니다.", 'success')
    else:
        flash("증거가 업로드된 상태의 일정만 완료 처리할 수 있습니다.", 'warning')
    return redirect(url_for('admin_punishment_requests'))

@app.route('/upload_punishment_evidence', methods=['GET'])
@app.route('/upload_punishment_evidence/<int:schedule_id>', methods=['GET', 'POST'])
def upload_punishment_evidence(schedule_id=None):
    if 'user_id' not in session: return flash("권한 없음", 'error'), redirect(url_for('login'))
    user_role = session.get('role')
    if schedule_id is None:
        query = PunishmentSchedule.query
        if user_role == 'sub':
            query = query.filter(PunishmentSchedule.user_id == session['user_id'], PunishmentSchedule.status.in_(['approved', 'rescheduled', 'evidence_uploaded']))
        else:
            query = query.filter(PunishmentSchedule.status == 'evidence_uploaded')
        schedules = query.order_by(db.desc(PunishmentSchedule.requested_datetime)).all()
        return render_template('upload_punishment_evidence.html', schedules=schedules, schedule_id=None, user_role=user_role)
    else:
        schedule = PunishmentSchedule.query.get_or_404(schedule_id)
        if user_role == 'sub' and schedule.user_id != session['user_id']:
            return flash("권한 없음", 'error'), redirect(url_for('home'))
        if request.method == 'POST':
            if user_role != 'sub' or schedule.status not in ['approved', 'rescheduled']:
                return flash("업로드 권한이 없습니다.", 'error'), redirect(url_for('upload_punishment_evidence', schedule_id=schedule_id))
            files = request.files.getlist('evidence_files')
            if len(files) < 3:
                return flash("증거 파일은 최소 3개 이상이어야 합니다.", 'error'), redirect(url_for('upload_punishment_evidence', schedule_id=schedule_id))
            filenames = [save_uploaded_file(f) for f in files if f and allowed_file(f.filename)]
            if len(filenames) != len(files):
                 return flash("파일 저장에 실패했거나 허용되지 않는 파일 형식입니다.", 'warning'), redirect(url_for('upload_punishment_evidence', schedule_id=schedule_id))
            schedule.evidence_filenames = json.dumps(filenames)
            schedule.evidence_uploaded = True 
            schedule.status = 'evidence_uploaded' 
            db.session.commit()
            flash("증거 파일이 성공적으로 업로드되었습니다.", 'success')
            return redirect(url_for('home'))
        
        evidence_files = []
        try:
            if schedule.evidence_filenames: evidence_files = json.loads(schedule.evidence_filenames)
        except (json.JSONDecodeError, TypeError): pass
        return render_template('upload_punishment_evidence.html', schedule=schedule, schedule_id=schedule_id, user_role=user_role, evidence_files=evidence_files)

@app.route('/payments', methods=['GET', 'POST'])
def payments():
    if 'user_id' not in session or session.get('role') != 'sub': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    user_id = session['user_id']
    if request.method == 'POST':
        amount = request.form.get('amount', type=int)
        description = request.form.get('description')
        image_file = request.files.get('image')
        if not amount or amount <= 0:
            return flash("유효한 금액을 입력해주세요.", 'error'), redirect(url_for('payments'))
        image_filename = save_uploaded_file(image_file)
        if not image_filename:
            return flash("명세서 사진은 필수입니다.", 'error'), redirect(url_for('payments'))
        new_payment = Payment(user_id=user_id, amount=amount, description=description, image_filename=image_filename)
        db.session.add(new_payment)
        db.session.commit()
        flash("결제 내역이 기록되었습니다.", 'success')
        return redirect(url_for('payments'))
    now = datetime.now()
    monthly_payments = Payment.query.filter(extract('year', Payment.timestamp) == now.year, extract('month', Payment.timestamp) == now.month, Payment.user_id == user_id).order_by(db.desc(Payment.timestamp)).all()
    monthly_total = sum(p.amount for p in monthly_payments)
    limit = 500000 
    return render_template('payments.html', monthly_payments=monthly_payments, monthly_total=monthly_total, limit=limit)

@app.route('/cardio', methods=['GET', 'POST'])
def cardio():
    if 'user_id' not in session or session.get('role') != 'sub': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    user_id = session['user_id']
    if request.method == 'POST':
        try:
            cardio_date = datetime.strptime(request.form.get('cardio_date'), '%Y-%m-%d').date()
            image_file = request.files.get('image')
            image_filename = save_uploaded_file(image_file)
            if not image_filename:
                return flash("인증 사진은 필수입니다.", 'error'), redirect(url_for('cardio'))
            if Cardio.query.filter_by(user_id=user_id, date=cardio_date).first():
                return flash(f"{cardio_date} 날짜의 기록이 이미 존재합니다.", 'warning'), redirect(url_for('cardio'))
            new_cardio = Cardio(user_id=user_id, date=cardio_date, image_filename=image_filename)
            db.session.add(new_cardio)
            db.session.commit()
            flash("유산소 운동이 기록되었습니다.", 'success')
            return redirect(url_for('cardio'))
        except (ValueError, TypeError):
            return flash("유효한 날짜를 입력해주세요.", 'error'), redirect(url_for('cardio'))
    today = date.today()
    start_of_week = today - timedelta(days=today.weekday()) 
    end_of_week = start_of_week + timedelta(days=6)
    weekly_cardio_logs = Cardio.query.filter(Cardio.user_id == user_id, Cardio.date.between(start_of_week, end_of_week)).all()
    recent_logs = Cardio.query.filter_by(user_id=user_id).order_by(db.desc(Cardio.timestamp)).limit(7).all() 
    return render_template('cardio.html', weekly_cardio_logs=weekly_cardio_logs, start_of_week=start_of_week, end_of_week=end_of_week, weekly_count=len(weekly_cardio_logs), recent_logs=recent_logs, today=today, weekly_dates=[start_of_week + timedelta(days=i) for i in range(7)]) 

@app.route('/weight', methods=['GET', 'POST'])
def weight():
    if 'user_id' not in session or session.get('role') != 'sub': return flash("권한이 없습니다.", 'error'), redirect(url_for('login'))
    user_id = session['user_id']
    if request.method == 'POST':
        weight_kg = request.form.get('weight_kg', type=float)
        if not weight_kg or weight_kg <= 0:
            return flash("유효한 체중을 입력해주세요.", 'error'), redirect(url_for('weight'))
        new_weight_entry = WeightEntry(user_id=user_id, weight_kg=weight_kg)
        db.session.add(new_weight_entry)
        db.session.commit()
        flash("체중이 기록되었습니다.", 'success')
        return redirect(url_for('weight'))
    weight_entries = WeightEntry.query.filter_by(user_id=user_id).order_by(WeightEntry.timestamp).all() 
    labels = [entry.timestamp.strftime('%m-%d') for entry in weight_entries]
    data = [entry.weight_kg for entry in weight_entries]
    return render_template('weight.html', weight_entries=weight_entries, chart_labels=json.dumps(labels), chart_data=json.dumps(data))

# [추가] DB 초기화를 위한 CLI 명령어
@app.cli.command("init-db")
def init_db_command():
    """데이터베이스 테이블을 생성하고 초기 사용자를 추가합니다."""
    init_db()
    print("Initialized the database.")

if __name__ == '__main__':
    app.run(debug=True)

