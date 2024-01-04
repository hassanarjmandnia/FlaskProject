from . import db
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _name = db.Column(db.String(50))
    _data = db.Column(db.String(10000))
    _path = db.Column(db.String(200))

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value


class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(250), unique=True)
    revoked_at = db.Column(db.DateTime, default=datetime.now())

    @classmethod
    def is_jti_blacklisted(cls, jti):
        return cls.query.filter_by(jti=jti).first() is not None


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _name = db.Column(db.String(50), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now(), nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=datetime.now())


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    _data = db.Column(db.String(10000))
    _date = db.Column(db.DateTime(timezone=True), default=datetime.now())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    likes = db.relationship('Like', backref='note', lazy=True, cascade='all, delete-orphan')

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    @property
    def date(self):
        return self._date

    @date.setter
    def date(self, value):
        self._date = value


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    _first_name = db.Column(db.String(150))
    _last_name = db.Column(db.String(150))
    _email = db.Column(db.String(150), unique=True)
    _password = db.Column(db.String(150))
    _is_active = db.Column(db.Boolean, default=False)
    _last_password_change = db.Column(db.DateTime, default=datetime.now())
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    notes = db.relationship('Note', backref='user', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('Like', backref='user', lazy=True, cascade='all, delete-orphan')

    @property
    def first_name(self):
        return self._first_name

    @first_name.setter
    def first_name(self, value):
        self._first_name = value

    @property
    def last_name(self):
        return self._last_name

    @last_name.setter
    def last_name(self, value):
        self._last_name = value

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        self._email = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    @property
    def last_password_change(self):
        return self._last_password_change

    @last_password_change.setter
    def last_password_change(self, value):
        self._last_password_change = value

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.role:
            default_role = Role.query.filter_by(_name='user').first()
            if not default_role:
                default_role = Role(_name='user')
                db.session.add(default_role)
                db.session.commit()
            self.role = default_role
