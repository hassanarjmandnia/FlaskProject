from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from .config import Config
from flask_caching import Cache

db = SQLAlchemy()
cache = Cache()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    Migrate(app, db)
    jwt = JWTManager(app)
    cache.init_app(app)
    from .models import User, RevokedToken
    from .api import api

    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    # login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    jwt.init_app(app)

    @jwt.token_in_blocklist_loader
    def is_token_revoked(jwt_header, jwt_data):
        jti = jwt_data['jti']
        return RevokedToken().is_jti_blacklisted(jti)

    api.init_app(app)
    return app
