from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_active = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_superadmin = db.Column(db.Boolean, default=False)
    ip_list = db.Column(db.Text, default="[]")  # JSON 문자열로 IP 저장

    # 관계
    ip_history = db.relationship("IPHistory", backref="user", cascade="all, delete-orphan")

    # 마지막 접속 IP / 위치
    @property
    def last_ip(self):
        if self.ip_history:
            return self.ip_history[-1].ip
        return None

    @property
    def last_geo(self):
        if self.ip_history:
            return self.ip_history[-1].location
        return None

    def add_ip(self, ip, location):
        new_entry = IPHistory(ip=ip, location=location, user=self)
        db.session.add(new_entry)
        db.session.commit()

class IPHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ip = db.Column(db.String(45))           # IPv6 포함
    location = db.Column(db.String(200))    # 위치 정보
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    is_anonymous = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref='suggestions')
    comments = db.relationship('Comment', backref='suggestion', cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    suggestion_id = db.Column(db.Integer, db.ForeignKey('suggestion.id'))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = db.relationship('User', backref='comments')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Ledger(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, default=datetime.utcnow)
    seungjung = db.Column(db.Integer, default=0)
    kuri = db.Column(db.Integer, default=0)
    sharp = db.Column(db.Integer, default=0)
    etc = db.Column(db.String(200), default="")
    nation_balance = db.Column(db.BigInteger, default=0)
    bico = db.Column(db.Float, default=0.0)
