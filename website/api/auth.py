from flask import abort, current_app
from functools import wraps
from flask_login import current_user
from datetime import datetime, timedelta

PASSWORD_CHANGE_THRESHOLD = 90


def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401, description='Login required')
        return f(*args, **kwargs)

    return decorated_function


def activation_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user._is_active:
            abort(401, description='Activation required')
        return f(*args, **kwargs)

    return decorated_function


def access_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.role.name != required_role:
                abort(403, description=f'Permission denied. {required_role} role required.')
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def password_change_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.last_password_change:
            days_since_last_change = (datetime.now() - current_user.last_password_change).days
            if days_since_last_change > PASSWORD_CHANGE_THRESHOLD:
                abort(403, description='Password change required.')
        return f(*args, **kwargs)

    return decorated_function


