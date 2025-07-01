# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, redirect, session, url_for
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'spank-secret-key'

# ✅ 사용자 계정 및 권한 설정
USERS = {
    'master': {'password': 'secret', 'role': 'owner'},
    'ddang': {'password': 'submit', 'role': 'sub'}
}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uid = request.form.get('username')
        pwd = request.form.get('password')
        user = USERS.get(uid)

        if user and pwd == user['password']:
            session['user'] = uid
            session['role'] = user['role']
            return redirect(url_for('home'))
        else:
            return render_template('login.html', error="잘못된 로그인 정보입니다.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/')
def home():
    if 'user' not in session:
        return redirect(url_for('login'))

    if session.get('role') == 'owner':
        try:
            with open('reports.txt', 'r', encoding='utf-8') as f:
                reports = f.read()
        except FileNotFoundError:
            reports = "(아직 제출된 보고서가 없습니다)"
        return render_template('dashboard.html', reports=reports)
    else:
        return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit():
    if 'user' not in session or session.get('role') != 'sub':
        return redirect(url_for('login'))

    report = request.form.get('report')
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open('reports.txt', 'a', encoding='utf-8') as f:
        f.write(f"[{now}] {session['user']}: {report}\n")
    return redirect('/')

@app.route('/history')
def history():
    if 'user' not in session or session.get('role') != 'sub':
        return redirect(url_for('login'))

    uid = session['user']
    lines = []
    try:
        with open('reports.txt', 'r', encoding='utf-8') as f:
            for line in f:
                if f"] {uid}:" in line:
                    lines.append(line.strip())
    except FileNotFoundError:
        lines = ["제출된 보고서가 없습니다."]

    return render_template('history.html', lines=lines)

@app.route('/delete_selected', methods=['POST'])
def delete_selected():
    if 'user' not in session or session.get('role') != 'sub':
        return redirect(url_for('login'))

    selected_lines = request.form.getlist('delete_lines')
    uid = session['user']

    try:
        with open('reports.txt', 'r', encoding='utf-8') as f:
            all_lines = f.readlines()

        with open('reports.txt', 'w', encoding='utf-8') as f:
            for line in all_lines:
                if line.strip() not in selected_lines:
                    f.write(line)
    except FileNotFoundError:
        pass

    return redirect(url_for('history'))

if __name__ == '__main__':
    print("Flask 서버 실행 중! http://0.0.0.0:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
