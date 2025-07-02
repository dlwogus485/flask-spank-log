# -*- coding: utf-8 -*-
import os
from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, flash, jsonify
from datetime import datetime, timedelta # timedelta는 여기서 임포트되어 사용됩니다.
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, extract
import json 

# Flask 애플리케이션 초기화
app = Flask(__name__)

# 시크릿 키 설정 (세션 관리에 필수)
# 실제 서비스에서는 환경 변수 등으로 관리하는 것이 강력히 권장됩니다.
app.secret_key = 'your_very_strong_and_secret_key_here_for_production_use' 

# 데이터베이스 설정
# SQLite 데이터베이스 파일을 'instance' 폴더에 'site.db'로 생성합니다.
# 'instance' 폴더는 Flask가 자동으로 생성하거나, 수동으로 생성할 수 있습니다.
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # SQLAlchemy 이벤트 시스템 비활성화 (성능 향상)
db = SQLAlchemy(app)

# 이미지 업로드 설정
UPLOAD_FOLDER = 'static/uploads' # 업로드된 이미지를 저장할 폴더 경로
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} # 허용되는 이미지 파일 확장자

# 업로드 폴더가 존재하지 않으면 생성합니다.
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 데이터베이스 모델 정의
# (이전과 동일하므로 생략)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False) # 'owner' or 'sub'
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)
    def __repr__(self): return f'<User {self.username}>'

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    is_late = db.Column(db.Boolean, default=False) 
    user = db.relationship('User', backref=db.backref('reports', lazy=True))
    def __repr__(self): return f'<Report {self.id} by {self.user.username}>'

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref=db.backref('payments', lazy=True))
    def __repr__(self): return f'<Payment {self.id} by {self.user.username} - {self.amount}>'

class BookReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_title = db.Column(db.String(255), nullable=False)
    page_count = db.Column(db.Integer, nullable=True)
    review_content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(120), nullable=True) 
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref=db.backref('book_reviews', lazy=True))
    def __repr__(self): return f'<BookReview {self.id} by {self.user.username} - {self.book_title}>'

class Cardio(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False) 
    image_filename = db.Column(db.String(120), nullable=True) 
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False) 
    user = db.relationship('User', backref=db.backref('cardio_logs', lazy=True))
    def __repr__(self): return f'<Cardio {self.id} by {self.user.username} - {self.date}>'

class WeightEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    weight_kg = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref=db.backref('weight_entries', lazy=True))
    def __repr__(self): return f'<WeightEntry {self.id} by {self.user.username} - {self.weight_kg}kg>'

class MealLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    meal_type = db.Column(db.String(20), nullable=False) 
    image_filename = db.Column(db.String(120), nullable=True) 
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)
    user = db.relationship('User', backref=db.backref('meal_logs', lazy=True))
    def __repr__(self): return f'<MealLog {self.id} by {self.user.username} - {self.meal_type}>'


# 데이터베이스 초기화 함수
def init_db():
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
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_uploaded_file(file):
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
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash("로그아웃 되었습니다.", 'info')
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') == 'owner':
        all_reports = Report.query.order_by(Report.timestamp.desc()).limit(10).all()
        all_payments = Payment.query.order_by(Payment.timestamp.desc()).limit(10).all()
        all_book_reviews = BookReview.query.order_by(BookReview.timestamp.desc()).limit(10).all()
        all_cardio_logs = Cardio.query.order_by(Cardio.timestamp.desc()).limit(10).all()
        all_weight_entries = WeightEntry.query.order_by(WeightEntry.timestamp.desc()).limit(10).all()
        all_meal_logs = MealLog.query.order_by(MealLog.timestamp.desc()).limit(10).all()

        return render_template('dashboard.html',
                               reports=all_reports,
                               payments=all_payments,
                               book_reviews=all_book_reviews,
                               cardio_logs=all_cardio_logs,
                               weight_entries=all_weight_entries,
                               meal_logs=all_meal_logs)
    else:
        return render_template('index.html') 

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------------------------------------------
# 10시 가상톡 (기존 보고서 제출 기능 확장)
# ---------------------------------------------------
@app.route('/submit_report', methods=['POST'])
def submit_report():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("보고서를 제출할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    report_content = request.form.get('report')
    now = datetime.now()
    
    forbidden_phrase = "한번만 봐주세요"
    if forbidden_phrase in report_content:
        flash(f"'{forbidden_phrase}' 문구는 사용할 수 없습니다. 다시 작성해주세요.", 'warning')
        return redirect(url_for('home')) 

    is_late = False
    if now.hour >= 22: 
        flash("10시 이후에 보고서를 제출하셨습니다. 벌점이 부과될 수 있습니다.", 'warning')
        is_late = True

    new_report = Report(
        user_id=session['user_id'],
        content=report_content,
        timestamp=now,
        is_late=is_late
    )
    db.session.add(new_report)
    db.session.commit()

    flash("보고서가 성공적으로 제출되었습니다!", 'success')
    return redirect(url_for('home'))

@app.route('/report_history')
def report_history():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("이력을 조회할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    user_reports = Report.query.filter_by(user_id=session['user_id']).order_by(Report.timestamp.desc()).all()
    return render_template('report_history.html', reports=user_reports)

@app.route('/delete_report_selected', methods=['POST'])
def delete_report_selected():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("보고서를 삭제할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    selected_report_ids = request.form.getlist('delete_ids') 
    
    for report_id in selected_report_ids:
        report_to_delete = Report.query.get(report_id)
        if report_to_delete and report_to_delete.user_id == session['user_id']:
            db.session.delete(report_to_delete)
    
    db.session.commit()
    flash("선택된 보고서가 삭제되었습니다.", 'success')
    return redirect(url_for('report_history'))

# ---------------------------------------------------
# 1. 소액결제 관리
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

# ---------------------------------------------------
# 2. 독후감 관리
# ---------------------------------------------------
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

# ---------------------------------------------------
# 3. 유산소 관리
# ---------------------------------------------------
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

    # 주간 날짜 리스트 생성 (템플릿으로 전달)
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
                           weekly_dates=weekly_dates) # <-- weekly_dates 추가

# ---------------------------------------------------
# 4. 체중 관리
# ---------------------------------------------------
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

# ---------------------------------------------------
# 8. 식사 인증
# ---------------------------------------------------
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


