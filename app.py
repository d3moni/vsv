import os
import json
import random
from datetime import date, datetime, timedelta
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from models import db, User, Suggestion, Comment, Ledger, IPHistory  # IPHistory 추가
from apscheduler.schedulers.background import BackgroundScheduler
from pytz import timezone
import requests


load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# 단일 DB (유저 + 장부)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)

with app.app_context():
    db.create_all()

    # 초기 관리자 계정 생성
    admin_username = os.environ.get("ADMIN_USERNAME", "1redrose")
    admin_password = os.environ.get("ADMIN_PASSWORD", "change_this_password!")
    if not User.query.filter_by(username=admin_username).first():
        admin_user = User(
            username=admin_username,
            password=generate_password_hash(admin_password),
            is_admin=True,
            is_active=True,
            is_superadmin=True
        )
        db.session.add(admin_user)
        db.session.commit()

# -------------------------
# 기본 라우트
# -------------------------
@app.route("/")
def index():
    user = User.query.get(session.get("user_id")) if "user_id" in session else None
    recommendations = [
        {"url": "/rules", "title": "규칙", "desc": "커뮤니티 규칙을 확인하세요"},
        {"url": "/profile", "title": "내 프로필", "desc": "회원 정보를 관리하세요"},
        {"url": "/info", "title": "정보", "desc": "서버 소식을 알아보세요"},
        {"url": "/suggestions", "title": "건의사항", "desc": "국가 발전에 기여하세요"},
        {"url": "/ledgerd", "title": "승증장부", "desc": "국가 잔고를 확인하세요"},
    ]
    selected = random.sample(recommendations, min(len(recommendations), 3))
    return render_template("index.html", user=user, selected=selected)

# -------------------------
# 회원가입 / 로그인 / 로그아웃
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("index"))  # 이미 로그인된 경우 메인 페이지로 리디렉션
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해주세요.")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("이미 존재하는 사용자입니다.")
            return redirect(url_for("register"))
        new_user = User(username=username, password=generate_password_hash(password), is_active=False)
        db.session.add(new_user)
        db.session.commit()
        flash("회원가입 완료! 관리자의 승인을 기다려주세요.")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        ip = request.remote_addr
        geo = "알수없음"  # 나중에 외부 API로 위치 가져오기 가능

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            # IP 기록 추가
            user.add_ip(ip, geo)

            flash("로그인 성공", "success")
            return redirect(url_for("index"))
        else:
            flash("아이디 또는 비밀번호가 잘못되었습니다.", "error")
            return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/user/<int:user_id>/ips")
def user_ips(user_id):
    user = User.query.get_or_404(user_id)
    geoips = [{"ip": ip.ip, "location": ip.geo} for ip in user.ip_history]
    return jsonify({"geoips": geoips})



@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("로그아웃 완료!")
    return redirect(url_for("index"))

# -------------------------
# 프로필 / 비밀번호 변경
# -------------------------
@app.route("/profile")
def profile():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    return render_template("profile.html", user=user)

@app.route("/profile/change_password", methods=["GET", "POST"])
def change_password():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        current_pw = request.form.get("current_password")
        new_pw = request.form.get("new_password")
        confirm_pw = request.form.get("confirm_password")
        if not check_password_hash(user.password, current_pw):
            flash("현재 비밀번호가 잘못되었습니다.")
            return redirect(url_for("change_password"))
        if new_pw != confirm_pw:
            flash("새 비밀번호와 확인 비밀번호가 일치하지 않습니다.")
            return redirect(url_for("change_password"))
        user.password = generate_password_hash(new_pw)
        db.session.commit()
        flash("비밀번호가 변경되었습니다.")
        return redirect(url_for("profile"))
    return render_template("change_password.html", user=user)

@app.route("/rules")
def rules():
    user = User.query.get(session.get("user_id")) if "user_id" in session else None
    return render_template("rules.html", user=user)

@app.route("/info")
def info():
    user = User.query.get(session.get("user_id")) if "user_id" in session else None
    return render_template("info.html", user=user)

# -------------------------
# 관리자 페이지
# -------------------------
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    current_user = User.query.get(session["user_id"])
    if not current_user.is_admin:
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for("index"))

    users = User.query.all()
    if request.method == "POST":
        action = request.form.get("action")
        target_id = request.form.get("user_id")
        target_user = User.query.get(int(target_id)) if target_id else None
        if not target_user:
            flash("사용자를 찾을 수 없습니다.")
            return redirect(url_for("admin"))
        if getattr(target_user, "is_superadmin", False):
            flash("최초 관리자 계정은 수정/삭제할 수 없습니다.")
            return redirect(url_for("admin"))
        if action == "approve":
            target_user.is_active = True
        elif action == "delete":
            db.session.delete(target_user)
        elif action == "make_admin":
            target_user.is_admin = True
        db.session.commit()
        flash(f"{target_user.username} 계정이 업데이트되었습니다.")
        return redirect(url_for("admin"))
    return render_template("admin.html", users=users, current_user=current_user)

# -------------------------
# 건의사항
# -------------------------
@app.route("/suggestions")
def view_suggestions():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    suggestions_list = Suggestion.query.order_by(Suggestion.created_at.desc()).all() if user.is_admin else Suggestion.query.filter(
        (Suggestion.is_public == True) | (Suggestion.author_id == user.id)
    ).order_by(Suggestion.created_at.desc()).all()
    return render_template("view_suggestions.html", user=user, suggestions=suggestions_list)

@app.route("/suggestions/submit", methods=["GET", "POST"])
def submit_suggestion():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        new_sug = Suggestion(
            title=request.form.get("title"),
            content=request.form.get("content"),
            author_id=user.id,
            is_public=bool(request.form.get("is_public")),
            is_anonymous=bool(request.form.get("is_anonymous"))
        )
        db.session.add(new_sug)
        db.session.commit()
        flash("건의사항이 제출되었습니다.")
        return redirect(url_for("view_suggestions"))
    return render_template("submit_suggestion.html", user=user)

@app.route("/suggestions/<int:sug_id>", methods=["GET", "POST"])
def suggestion_detail(sug_id):
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    suggestion = Suggestion.query.get_or_404(sug_id)
    if not suggestion.is_public and not (user.is_admin or user.id == suggestion.author_id):
        flash("이 건의사항을 볼 수 없습니다.")
        return redirect(url_for("view_suggestions"))
    if request.method == "POST":
        comment_content = request.form.get("comment")
        if comment_content:
            comment = Comment(suggestion_id=suggestion.id, author_id=user.id, content=comment_content)
            db.session.add(comment)
            db.session.commit()
            flash("댓글이 등록되었습니다.")
            return redirect(url_for("suggestion_detail", sug_id=sug_id))
    return render_template("suggestion_detail.html", user=user, suggestion=suggestion)

@app.route("/suggestions/delete/<int:sug_id>", methods=["POST"])
def delete_suggestion(sug_id):
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    if not user.is_admin:
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for("view_suggestions"))
    suggestion = Suggestion.query.get_or_404(sug_id)
    db.session.delete(suggestion)
    db.session.commit()
    flash("건의사항이 삭제되었습니다.")
    return redirect(url_for("view_suggestions"))

# -------------------------
# 장부
# -------------------------
@app.route("/ledger")
def view_ledger():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session.get("user_id"))

    # 한국 시간 기준 오늘
    kst = timezone("Asia/Seoul")
    today = datetime.now(kst).date()

    ledger_entry = Ledger.query.filter_by(date=today).first()
    return render_template("ledger.html", ledger=ledger_entry, user=user)

# -------------------------
# 특정 날짜 장부 보기
# -------------------------
@app.route("/ledger/<string:ledger_date>")
def ledger_by_date(ledger_date):
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session.get("user_id"))

    # 날짜 형식 검증
    try:
        d = datetime.strptime(ledger_date, "%Y-%m-%d").date()
    except ValueError:
        flash("잘못된 날짜 형식입니다.")
        return redirect(url_for("view_ledger"))

    ledger_entry = Ledger.query.filter_by(date=d).first()
    return render_template("ledger.html", ledger=ledger_entry, user=user)

# -------------------------
# 장부 수정 (관리자 전용)
# -------------------------
@app.route("/ledger/edit", methods=["GET", "POST"])
def edit_ledger():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session.get("user_id"))
    if not user.is_admin:
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for("index"))

    # 한국 시간 기준 오늘
    kst = timezone("Asia/Seoul")
    today = datetime.now(kst).date()
    ledger_entry = Ledger.query.filter_by(date=today).first()

    if request.method == "POST":
        seungjung = int(request.form.get("seungjung", 0))
        kuri = int(request.form.get("kuri", 0))
        sharp = int(request.form.get("sharp", 0))
        etc = request.form.get("etc", "")
        nation_balance = int(request.form.get("nation_balance", 0))
        bico = float(request.form.get("bico", 0))

        if not ledger_entry:
            ledger_entry = Ledger(
                date=today,
                seungjung=seungjung,
                kuri=kuri,
                sharp=sharp,
                etc=etc,
                nation_balance=nation_balance,
                bico=bico
            )
            db.session.add(ledger_entry)
        else:
            ledger_entry.seungjung = seungjung
            ledger_entry.kuri = kuri
            ledger_entry.sharp = sharp
            ledger_entry.etc = etc
            ledger_entry.nation_balance = nation_balance
            ledger_entry.bico = bico

        db.session.commit()
        flash("장부가 저장되었습니다.")
        return redirect(url_for("view_ledger"))

    return render_template("edit_ledger.html", ledger=ledger_entry, user=user)


# -------------------------
# 장부 자동 복사 기능
# -------------------------
def copy_ledger_if_not_modified():
    with app.app_context():
        kst = timezone("Asia/Seoul")
        today = datetime.now(kst).date()
        yesterday = today - timedelta(days=1)

        # 오늘 기록이 있는지 확인
        today_record = Ledger.query.filter_by(date=today).first()
        if today_record:
            return  # 이미 있으면 복사 안 함

        # 어제 기록 가져오기
        yesterday_record = Ledger.query.filter_by(date=yesterday).first()
        if yesterday_record:
            new_record = Ledger(
                date=today,
                seungjung=yesterday_record.seungjung,
                kuri=yesterday_record.kuri,
                sharp=yesterday_record.sharp,
                etc=yesterday_record.etc,
                nation_balance=yesterday_record.nation_balance,
                bico=yesterday_record.bico
            )
            db.session.add(new_record)
            db.session.commit()
            print(f"✅ {today} 장부가 어제 기록에서 자동 복사되었습니다.")

# -------------------------
# 스케줄러 실행 (매일 00:00 KST 기준)
# -------------------------
scheduler = BackgroundScheduler(timezone="Asia/Seoul")
scheduler.add_job(func=copy_ledger_if_not_modified, trigger="cron", hour=0, minute=0)
scheduler.start()

if __name__ == "__main__":
    app.run(debug=False)
