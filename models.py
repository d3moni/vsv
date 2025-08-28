from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=False)  # 승인 여부
    is_admin = db.Column(db.Boolean, default=False)   # 관리자 여부
    is_superadmin = db.Column(db.Boolean, default=False)  # 최초 관리자 구분용
