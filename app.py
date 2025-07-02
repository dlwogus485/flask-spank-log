# -*- coding: utf-8 -*-
import os
from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, flash
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Flask 애플리케이션 초기화
app = Flask(__name__)

# 시크릿 키 설정 (세션 관리에 사용)
# 실제 서비스에서는 환경 변수 등으로 관리하는 것이 좋습니다.
app.secret_key = 'your_very_secret_key_here_for_production' # 보안 강화를 위해 더 복잡한 키 사용 권장

# 데이터베이스 설정
# SQLite 데이터베이스 파일을 'instance' 폴더에 'site.db'로 생성
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 이미지 업로드 설정
UPLOAD_FOLDER = 'static/uploads' # 업로드된 이미지를 저장할 폴더
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} # 허용되는 이미지 확장자
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 업로드 폴더가 없으면 생성
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 데이터베이스 모델 정의
# User 모델: 사용자 정보 (id, 사용자명, 비밀번호 해시, 역할)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False) # 'owner' 또는 'sub'

    # 비밀번호 해싱 메서드
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # 비밀번호 확인 메서드
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# Report 모델: 보고서 정보 (id, 사용자 ID, 내용, 이미지 파일명, 제출 시간)
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(120), nullable=True) # 이미지 파일명 저장
    timestamp = db.Column(db.DateTime, default=datetime.now, nullable=False)

    user = db.relationship('User', backref=db.backref('reports', lazy=True))

    def __repr__(self):
        return f'<Report {self.id} by {self.user.username}>'

# 데이터베이스 초기화 함수
def init_db():
    with app.app_context():
        db.create_all() # 모든 모델에 해당하는 테이블 생성

        # 초기 사용자 추가 (이미 존재하지 않을 경우)
        if not User.query.filter_by(username='master').first():
            master = User(username='master', role='owner')
            master.set_password('secret')
            db.session.add(master)
        if not User.query.filter_by(username='ddang').first():
            ddang = User(username='ddang', role='sub')
            ddang.set_password('submit')
            db.session.add(ddang)
        db.session.commit()

# 허용된 파일 확장자인지 확인하는 함수
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 로그인 라우트
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uid = request.form.get('username')
        pwd = request.form.get('password')
        user = User.query.filter_by(username=uid).first() # 데이터베이스에서 사용자 조회

        if user and user.check_password(pwd): # 해싱된 비밀번호 확인
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('home'))
        else:
            flash("잘못된 로그인 정보입니다.", 'error') # 에러 메시지 표시
            return render_template('login.html', error="잘못된 로그인 정보입니다.")
    return render_template('login.html')

# 로그아웃 라우트
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash("로그아웃 되었습니다.", 'info')
    return redirect(url_for('login'))

# 홈 라우트
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if session.get('role') == 'owner':
        # 'owner'는 모든 보고서 조회
        reports = Report.query.order_by(Report.timestamp.desc()).all()
        return render_template('dashboard.html', reports=reports)
    else:
        return render_template('index.html')

# 보고서 제출 라우트
@app.route('/submit', methods=['POST'])
def submit():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("보고서를 제출할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    report_content = request.form.get('report')
    image_file = request.files.get('image') # 'image'는 HTML 폼의 input name과 일치해야 함

    image_filename = None
    if image_file and allowed_file(image_file.filename):
        filename = secure_filename(image_file.filename)
        # 파일명 중복 방지를 위해 타임스탬프 추가
        unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
        image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        image_filename = unique_filename
    elif image_file and not allowed_file(image_file.filename):
        flash("허용되지 않는 파일 형식입니다. (png, jpg, jpeg, gif만 가능)", 'warning')
        return redirect(url_for('home'))

    # 새 보고서 객체 생성 및 데이터베이스에 추가
    new_report = Report(
        user_id=session['user_id'],
        content=report_content,
        image_filename=image_filename
    )
    db.session.add(new_report)
    db.session.commit()

    flash("보고서가 성공적으로 제출되었습니다!", 'success')
    return redirect(url_for('home'))

# 제출 이력 라우트
@app.route('/history')
def history():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("이력을 조회할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    # 현재 로그인한 사용자의 보고서만 조회
    user_reports = Report.query.filter_by(user_id=session['user_id']).order_by(Report.timestamp.desc()).all()
    return render_template('history.html', reports=user_reports)

# 선택된 보고서 삭제 라우트
@app.route('/delete_selected', methods=['POST'])
def delete_selected():
    if 'user_id' not in session or session.get('role') != 'sub':
        flash("보고서를 삭제할 권한이 없습니다.", 'error')
        return redirect(url_for('login'))

    selected_report_ids = request.form.getlist('delete_ids') # 보고서 ID 목록을 받음
    
    # 선택된 각 보고서 ID에 대해 삭제 처리
    for report_id in selected_report_ids:
        report_to_delete = Report.query.get(report_id)
        # 현재 사용자의 보고서인지 확인 (보안 강화)
        if report_to_delete and report_to_delete.user_id == session['user_id']:
            # 이미지 파일이 있으면 삭제
            if report_to_delete.image_filename:
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], report_to_delete.image_filename)
                if os.path.exists(image_path):
                    os.remove(image_path)
            db.session.delete(report_to_delete)
    
    db.session.commit()
    flash("선택된 보고서가 삭제되었습니다.", 'success')
    return redirect(url_for('history'))

# 업로드된 이미지를 제공하는 라우트
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# 애플리케이션 실행
if __name__ == '__main__':
    # 데이터베이스 초기화 (테이블 생성 및 초기 사용자 추가)
    init_db()
    print("Flask 서버 실행 중! http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)

