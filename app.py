import os
from flask import Flask, render_template, request, redirect, session, url_for, flash
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# 보안: 시크릿키를 환경변수에서 읽음
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

with app.app_context():
    db.create_all()

    # ===============================
    # 🔹 초기 관리자 계정 생성 (환경변수 사용)
    # ===============================
    admin_username = os.environ.get("ADMIN_USERNAME", "1redrose")
    admin_password = os.environ.get("ADMIN_PASSWORD", "change_this_password!")

    if not User.query.filter_by(username=admin_username).first():
        admin_user = User(
            username=admin_username,
            password=generate_password_hash(admin_password),
            is_admin=True,
            is_active=True
        )
        db.session.add(admin_user)
        db.session.commit()
        # 배포시 프린트문 제거 또는 로그로 대체
        # print(f"관리자 계정 생성 완료: {admin_username} / {admin_password}")


@app.route("/")
def index():
    if "user_id" in session:
        user = User.query.get(session["user_id"])
        return render_template("index.html", user=user)
    return render_template("index.html", user=None)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해주세요.")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("이미 존재하는 사용자입니다.")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        # 가입 시 기본적으로 비활성(is_active=False)
        new_user = User(username=username, password=hashed_pw, is_active=False, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash("회원가입 완료! 관리자의 승인을 기다려주세요.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not username or not password:
            flash("아이디와 비밀번호를 모두 입력해주세요.")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=username).first()
        if not user:
            flash("아이디 또는 비밀번호가 잘못되었습니다.")
            return redirect(url_for("login"))

        if not user.is_active:
            flash("관리자가 승인해야 로그인할 수 있습니다.")
            return redirect(url_for("login"))

        if check_password_hash(user.password, password):
            session["user_id"] = user.id
            flash("로그인 성공!")
            return redirect(url_for("index"))
        else:
            flash("아이디 또는 비밀번호가 잘못되었습니다.")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("로그아웃 완료!")
    return redirect(url_for("index"))


# ===============================
# 🔹 관리자 페이지
# ===============================
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "user_id" not in session:
        flash("로그인이 필요합니다.")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    if not user.is_admin:
        flash("관리자 권한이 필요합니다.")
        return redirect(url_for("index"))

    users = User.query.all()

    if request.method == "POST":
        action = request.form.get("action")
        target_id = request.form.get("user_id")
        target_user = User.query.get(target_id)

        if action == "approve":
            target_user.is_active = True
            db.session.commit()
            flash(f"{target_user.username} 계정이 승인되었습니다.")
        elif action == "delete":
            db.session.delete(target_user)
            db.session.commit()
            flash(f"{target_user.username} 계정이 삭제되었습니다.")

        return redirect(url_for("admin"))

    return render_template("admin.html", users=users)


@app.route("/rules")
def rules():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    return render_template("rules.html", user=user)


if __name__ == "__main__":
    # 배포시 debug=False 유지
    app.run(debug=False)
