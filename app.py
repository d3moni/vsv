import os
from flask import Flask, render_template, request, redirect, session, url_for, flash
from models import db, User, Suggestion, Comment
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

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


@app.route("/")
def index():
    user = None
    if "user_id" in session:
        user = User.query.get(session["user_id"])
    return render_template("index.html", user=user)


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
        session["user_id"] = user.id
        flash("로그인 성공!")
        return redirect(url_for("index"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("로그아웃 완료!")
    return redirect(url_for("index"))


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
        if not target_id:
            flash("잘못된 요청입니다.")
            return redirect(url_for("admin"))
        try:
            target_user = User.query.get(int(target_id))
        except ValueError:
            flash("잘못된 사용자 ID입니다.")
            return redirect(url_for("admin"))
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
    return render_template("admin.html", users=users)


@app.route("/rules")
def rules():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    return render_template("rules.html", user=user)


@app.route("/info")
def info():
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = User.query.get(session["user_id"])
    return render_template("info.html", user=user)


from flask import render_template, request, redirect, session, flash, url_for
from models import db, Suggestion, Comment, User

# 건의사항 목록 페이지
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


# 건의사항 등록 페이지
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
            author_id=None if is_anonymous else user.id,
            is_public=is_public,
            is_anonymous=is_anonymous
        )
        db.session.add(new_sug)
        db.session.commit()
        flash("건의사항이 제출되었습니다.")
        return redirect(url_for("view_suggestions"))

    return render_template("submit_suggestion.html", user=user)


# 개별 건의사항 상세 페이지 (댓글 가능)
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




if __name__ == "__main__":
    app.run(debug=False)
