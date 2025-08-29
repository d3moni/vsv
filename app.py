import os
import json
import random
import requests
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from models import db, User, Suggestion, Comment

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

    # 초기 관리자 계정
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
    user = None
    if "user_id" in session:
        user = User.query.get(session["user_id"])

    recommendations = [
        {"url": "/rules", "title": "규칙", "desc": "커뮤니티 규칙을 확인하세요"},
        {"url": "/profile", "title": "내 프로필", "desc": "회원 정보를 관리하세요"},
        {"url": "/info", "title": "정보", "desc": "서버 소식을 알아보세요"},
        {"url": "/suggestions", "title": "건의사항", "desc": "국가 발전에 기여하세요"},
    ]
    selected = random.sample(recommendations, min(len(recommendations), 3))
    return render_template("index.html", user=user, selected=selected)

# -------------------------
# 회원가입 / 로그인 / 로그아웃
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해주세요.")
            return redirect(url_for("register"))
        if User.query.filter_by(username=username).first():
            flash("이미 존재하는 사용자입니다.")
            return redirect(url_for("register"))
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw, is_active=False)
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
        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해주세요.")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash("아이디 또는 비밀번호가 잘못되었습니다.")
            return redirect(url_for("login"))
        if not user.is_active:
            flash("관리자가 승인해야 로그인할 수 있습니다.")
            return redirect(url_for("login"))

        # 로그인 IP 기록
        ip = request.remote_addr
        ip_list = json.loads(user.ip_history)
        geo_list = json.loads(user.geoip_history)
        if ip not in ip_list:
            ip_list.append(ip)
            try:
                resp = requests.get(f"https://ipinfo.io/{ip}/json")
                if resp.status_code == 200:
                    data = resp.json()
                    location = f"{data.get('city','')}, {data.get('region','')}, {data.get('country','')}"
                else:
                    location = "Unknown"
            except:
                location = "Unknown"
            geo_list.append({"ip": ip, "location": location})
            user.ip_history = json.dumps(ip_list)
            user.geoip_history = json.dumps(geo_list)
            db.session.commit()

        session["user_id"] = user.id
        flash("로그인 성공!")
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("로그아웃 완료!")
    return redirect(url_for("index"))

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
        if not target_id:
            flash("잘못된 요청입니다.")
            return redirect(url_for("admin"))
        target_user = User.query.get(int(target_id))
        if not target_user:
            flash("사용자를 찾을 수 없습니다.")
            return redirect(url_for("admin"))
        if getattr(target_user, "is_superadmin", False):
            flash("최초 관리자 계정은 수정/삭제할 수 없습니다.")
            return redirect(url_for("admin"))
        if action == "approve":
            target_user.is_active = True
            db.session.commit()
            flash(f"{target_user.username} 계정이 승인되었습니다.")
        elif action == "delete":
            db.session.delete(target_user)
            db.session.commit()
            flash(f"{target_user.username} 계정이 삭제되었습니다.")
        elif action == "make_admin":
            if not target_user.is_admin:
                target_user.is_admin = True
                db.session.commit()
                flash(f"{target_user.username} 계정에 관리자 권한이 부여되었습니다.")
            else:
                flash(f"{target_user.username} 계정은 이미 관리자입니다.")
        return redirect(url_for("admin"))

    return render_template("admin.html", users=users, current_user=current_user)

# API: 유저 IP/위치 JSON
@app.route("/user/<int:user_id>/ips")
def user_ips(user_id):
    current_user = User.query.get(session.get("user_id"))
    if not current_user or not current_user.is_superadmin:
        return jsonify({"error": "권한 없음"}), 403
    user = User.query.get_or_404(user_id)
    geo_list = json.loads(user.geoip_history)
    return jsonify({"geoips": geo_list})

# -------------------------
# 건의사항 관련
# -------------------------
@app.route("/suggestions")
def view_suggestions():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    if user.is_admin:
        suggestions_list = Suggestion.query.order_by(Suggestion.created_at.desc()).all()
    else:
        suggestions_list = Suggestion.query.filter(
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
        title = request.form.get("title")
        content = request.form.get("content")
        is_public = bool(request.form.get("is_public"))
        is_anonymous = bool(request.form.get("is_anonymous"))
        new_sug = Suggestion(
            title=title,
            content=content,
            author_id=user.id,
            is_public=is_public,
            is_anonymous=is_anonymous
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
            comment = Comment(
                suggestion_id=suggestion.id,
                author_id=user.id,
                content=comment_content
            )
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


if __name__ == "__main__":
    app.run(debug=False)
