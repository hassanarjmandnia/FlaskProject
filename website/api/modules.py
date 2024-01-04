import json
import os
import re
import threading
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from flask import current_app, jsonify
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_jwt)
from flask_login import login_user, logout_user, current_user
from flask_restful import marshal
from pathlib import Path
from redis import Redis
from website import db
from website.api.parser_resource_fields import (note_resource_fields, role_parser, user_resource_fields,
                                                role_resource_fields, likers_resource_fields)
from website.models import User, Note, Like, Role, RevokedToken, File
from werkzeug.security import generate_password_hash, check_password_hash


class RedisManager():
    def __init__(self):
        self.redis = Redis(host='localhost', port=6379, db=0)
        self.result_data = {'sets': {}}

    def read_the_file(self, data, file_name):
        for item in data:
            tweet_info = item["_"]
            tweet_type = tweet_info["type"]
            if tweet_type == "tweet":
                self.preparation(item)

    def preparation(self, item):
        text_content = item['text']
        hashtags = re.findall(r'#(\w+)', text_content)
        created_at = item['created_at']
        self.hashtag_optimization(hashtags, created_at)
        is_quoted = item['is_quote_status']
        if is_quoted:
            self.preparation_of_quoted_tweet(item)

    def preparation_of_quoted_tweet(self, item):
        quoted_tweet = item['quoted_status']
        quoted_tweet_info = quoted_tweet["_"]
        quoted_tweet_type = quoted_tweet_info["type"]
        if quoted_tweet_type == "tweet":
            hashtags = re.findall(r'#(\w+)', quoted_tweet['text'])
            created_at = quoted_tweet['created_at']
            self.hashtag_optimization(hashtags, created_at)

    def hashtag_optimization(self, hashtags, created_at):
        created_at_datetime = datetime.strptime(created_at, '%a %b %d %H:%M:%S +0000 %Y')
        hour = self.get_hour_number(created_at_datetime)
        for hashtag in hashtags:
            self.add_hashtag_to_zset(hashtag, hour)

    def add_hashtag_to_zset(self, hashtag, hour):
        self.redis.zadd(f'hashtag{hour}', {hashtag: 1}, incr=True)
        self.redis.zadd(f'hashtags', {hashtag: 1}, incr=True)

    def get_hour_number(self, time):
        hour = time.hour
        if 0 <= hour < 24:
            return hour + 1
        else:
            raise ValueError("Invalid input or out-of-range hour")

    def create_zsets(self):
        for i in range(1, 25):
            set_name = f'hashtag{i}'
            self.redis.zrange(set_name, 0, -1)
        self.redis.zrange('hashtags', 0, -1)

    def clear_zsets(self):
        for i in range(1, 25):
            set_name = f'hashtag{i}'
            self.redis.zremrangebyrank(set_name, 0, -1)
        self.redis.zremrangebyrank('hashtags', 0, -1)

    def get_top_elements(self, set_name, top_n=3):
        top_elements = self.redis.zrevrange(set_name, 0, top_n - 1, withscores=True)
        decoded_top_elements = [(element.decode('utf-8'), score)
                                if isinstance(element, bytes) else
                                (element, score)
                                for element, score in top_elements]
        return decoded_top_elements

    def show(self):
        for i in range(1, 25):
            set_name = f'hashtag{i}'
            top_elements = self.get_top_elements(set_name)
            self.result_data['sets'][set_name] = [{'element': element, 'score': score} for element, score in
                                                  top_elements]
        top_elements = self.get_top_elements('hashtags', top_n=10)
        self.result_data['sets']['hashtags'] = [{'element': element, 'score': score} for element, score in top_elements]
        return (self.result_data)

    def manager(self):
        desktop_path = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/files/tweets')
        json_files = [file for file in os.listdir(desktop_path) if file.endswith('.json')]
        self.create_zsets()
        self.clear_zsets()
        for file_name in json_files:
            file_path = os.path.join(desktop_path, file_name)
            with open(file_path, 'r', encoding='utf-8') as file:
                decoder = json.JSONDecoder()
                data = decoder.decode(file.read())
            self.read_the_file(data, file_name)
        return self.show()


class TestManager():

    def worker_1(self, data, file_name):
        for item in data:
            tweet_info = item.get("_", {})
            tweet_type = tweet_info.get("type", "")
            if tweet_type == "tweet":
                item = self.worker_2(item)
        self.worker_3(file_name, data)

    def worker_2(self, item):
        text_content = item.get('text', '')
        hashtags = re.findall(r'#(\w+)', text_content)
        item['_']['hashtags'] = hashtags
        return item

    def worker_3(self, file_name, data):
        new_file_path = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/files/tweets/new',
                                     'new_' + file_name)
        with open(new_file_path, 'w', encoding='utf-8') as new_file:
            json.dump(data, new_file, ensure_ascii=False, indent=4)

    def manager(self):
        desktop_path = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/files/tweets')
        json_files = [file for file in os.listdir(desktop_path) if file.endswith('.json')]

        for file_name in json_files:
            file_path = os.path.join(desktop_path, file_name)
            with open(file_path, 'r', encoding='utf-8') as file:
                decoder = json.JSONDecoder()
                data = decoder.decode(file.read())
            self.worker_1(data, file_name)

        return "Processing completed for all files"


class ThereadPoolManager():

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=20)
        self.app = current_app._get_current_object()

    def extract_hashtags(self, item):
        text_content = item.get('text', '')
        hashtags = re.findall(r'#(\w+)', text_content)
        item['_']['hashtags'] = hashtags
        return item

    def save_the_new_file(self, file_name, data):
        new_file_path = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/files/tweets/new',
                                     'new_' + file_name)
        with open(new_file_path, 'w', encoding='utf-8') as new_file:
            json.dump(data, new_file, ensure_ascii=False, indent=4)

    def process_item(self, item):
        tweet_info = item.get("_", {})
        tweet_type = tweet_info.get("type", "")
        if tweet_type == "tweet":
            return self.extract_hashtags(item)
        return item

    def process_file(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            decoder = json.JSONDecoder()
            data = decoder.decode(file.read())
        futures = [self.executor.submit(self.process_item, item) for item in data]
        # concurrent.futures.wait(futures)
        updated_data = [future.result() for future in futures]
        file_name = os.path.basename(file_path)
        self.save_the_new_file(file_name, updated_data)

    def manager(self):
        desktop_path = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop/files/tweets')
        json_files = [file for file in os.listdir(desktop_path) if file.endswith('.json')]
        futures = [self.executor.submit(self.process_file, os.path.join(desktop_path, file_name))
                   for file_name in json_files]
        # concurrent.futures.wait(futures)
        results = [future.result() for future in futures]
        return "Processing completed for all files"


class SuperadminManager():
    def __init__(self, user_id, logger, parser=None):
        self.parser = parser
        self.user_id = user_id
        self.db_con = Database(db)
        self.logger = logger

    def update_state_of_user(self):
        user = User.query.get_or_404(self.user_id)
        if user._is_active:
            self.db_con.update_user_state(user)
            return {'message': 'User Got Inactivated'}, 200
        else:
            self.db_con.update_user_state(user)
            return {'message': 'User Got Activated'}, 200

    def update_role_of_user(self):
        args = self.parser.parse_args()
        user = User.query.get_or_404(self.user_id)
        role = Role.query.filter_by(_name=args['name']).first()
        if role:
            self.db_con.update_user_role(user, role.id)
            return marshal(user, user_resource_fields), 200
        else:
            return {'message': 'U are a superadmin?! u don\'t even know the name of Roles!'}, 403

    def delete_user(self):
        user = User.query.get_or_404(self.user_id)
        self.db_con.delete_user(user)
        return marshal(user, user_resource_fields), 200


class NoteLikeManager():
    def __init__(self, note_id, logger):
        self.id = note_id
        self.db_con = Database(db)
        self.logger = logger

    def show(self):
        note = Note.query.get_or_404(self.id)
        if Validators().note_belong_to_user(note) or current_user.role._name == 'superadmin':
            users_who_liked_note = [like.user for like in note.likes]
            return marshal(users_who_liked_note, likers_resource_fields), 200
        return {'message': 'This note dosen\'t belong to you'}, 403

    def add(self):
        note = Note.query.get_or_404(self.id)
        existing_like = Like.query.filter_by(user_id=current_user.id, note_id=self.id).first()
        if existing_like:
            self.db_con.delete_like(existing_like)
            return {'message': 'You Unlike the note'}, 200
        else:
            self.db_con.add_like(self.id)
            return {'message': 'You like the note'}, 200


class UserLikenManager():
    def __init__(self, logger):
        self.likes = [like.note for like in current_user.likes]
        self.logger = logger

    def show(self):
        if self.likes:
            return {'Likes': marshal(self.likes, note_resource_fields)}, 200
        else:
            return {'message': 'You don\'t like anything.'}, 404


class RoleManager():
    def __init__(self, parser, logger):
        self.parser = parser

    def add(self):
        if self.parser:
            args = self.parser.parse_args()
            name = args['name']
            role = Role.query.filter_by(_name=name).first()
            if not role:
                new_role = Role(_name=args['name'])
                db.session.add(new_role)
                db.session.commit()
                return {'Role': marshal(new_role, role_resource_fields)}, 201
            else:
                return {'message': 'This role already exists.'}, 409
        else:
            raise ValueError("Parser is required for adding a role.")


class NoteManager():
    def __init__(self, note_id, logger, parser=None):
        self.parser = parser
        self.id = note_id
        self.db_con = Database(db)
        self.logger = logger

    def show(self):
        note = Note.query.get_or_404(self.id)
        return {'note': marshal(note, note_resource_fields)}, 200

    def update(self):
        if self.parser:
            args = self.parser.parse_args()
            note = Note.query.get_or_404(self.id)
            if Validators().note_belong_to_user(note):
                self.db_con.update_note(note, args['data'])
                return {'note': marshal(note, note_resource_fields)}, 200
            else:
                return {'message': 'This note does not belong to you'}, 403
        else:
            raise ValueError("Parser is required for updating a note.")

    def delete(self):
        note = Note.query.get_or_404(self.id)
        if Validators().note_belong_to_user(note) or current_user.role._name == 'superadmin':
            self.db_con.delete_note(note)
            return {'note': marshal(note, note_resource_fields)}, 200
        else:
            return {'message': 'This note does not belong to you'}, 403


class NoteHandler():
    def __init__(self, logger, cache, parser=None):
        self.parser = parser
        self.db_con = Database(db)
        self.logger = logger
        self.cache = cache

    def show(self):
        print('Cache Miss!')
        notes = Note.query.all()
        if not notes:
            return [], 204
        self.logger['info'].info(f"[{__name__}.{self.__class__.__name__}.show] - Showing All the Notes!")
        return marshal(notes, note_resource_fields), 200

    def add(self):
        if self.parser:
            args = self.parser.parse_args()
            new_note = self.db_con.add_new_note(args['data'])
            if self.cache:
                self.cache.delete('all_notes')
            return marshal(new_note, note_resource_fields), 200
        else:
            raise ValueError("Parser is required for adding a note.")


class JwtRevoke():
    def __init__(self):
        self.db_con = Database(db)

    def add_token_to_blacklist(self):
        jti = get_jwt()["jti"]
        revoked_token = RevokedToken(jti=jti)
        self.db_con.add_to_database(revoked_token)
        self.db_con.commit_changes()

    def is_token_revoked(decoded_token):
        jti = decoded_token['jti']
        return RevokedToken.query.filter_by(jti=jti).first() is not None


class PasswordChangeManager():
    def __init__(self, parser, logger):
        self.parser = parser
        self.validator = Validators(self.parser)
        self.db_con = Database(db)
        self.logger = logger

    def change_password(self):
        validation_result = self.validator.password_change_validator()
        if isinstance(validation_result, list):
            return {'message': 'Invalid  data', 'errors': validation_result}, 400
        self.db_con.update_user_password(current_user, validation_result['new_password'])
        return {'message': 'Password Changed successfully'}, 200


class UserLoginManager():
    def __init__(self, parser, logger):
        self.parser = parser
        self.validator = Validators(self.parser)
        self.logger = logger

    def login_user(self):
        validation_result = self.validator.user_login_validator()
        if isinstance(validation_result, list):
            return {'message': 'Invalid Log-in data', 'errors': validation_result}, 400

        user = User.query.filter_by(_email=validation_result['email']).first()
        login_user(user)
        return {'message': 'User Logged in successfully'}, 200

        '''
        access_token = create_access_token(identity=validation_result['email'])
        refresh_token = create_refresh_token(identity=validation_result['email'])

        return {
            'message': 'User Logged-in successfully',
            'access_token': access_token,
            'refresh_token': refresh_token
        }, 200
        '''


class UserRegistrationManager():
    def __init__(self, parser, logger):
        self.parser = parser
        self.db_con = Database(db)
        self.logger = logger
        self.validator = Validators(self.parser)

    def register_user(self):
        validation_result = self.validator.user_registration_validator()
        if isinstance(validation_result, list):
            return {'message': 'Invalid registration data', 'errors': validation_result}, 400
        new_user = self.db_con.add_user(validation_result['email'], validation_result['firstname'],
                                        validation_result['lastname'], validation_result['password'])

        login_user(new_user, remember=True)
        return {'message': 'User registered successfully'}, 201

        '''
         access_token = create_access_token(identity=validation_result['email'])
         refresh_token = create_refresh_token(identity=validation_result['email'])

         return {
             'message': 'User Logged-in successfully',
             'access_token': access_token,
             'refresh_token': refresh_token
         }, 200
        '''


class Validators():
    def __init__(self, parser=None):
        self.parser = parser

    def user_registration_validator(self):
        args = self.parser.parse_args()
        email = args['email']
        password1 = args['password']
        password2 = args['password2']
        first_name = args['firstname']
        last_name = args['lastname']

        validation_errors = []
        user = User.query.filter_by(_email=email).first()
        if user:
            validation_errors.append('Email already exists.')
        elif len(email) < 4:
            validation_errors.append('Email must be at least 4 characters long.')
        elif '@' not in email:
            validation_errors.append("Email must have the correct format.")
        elif len(first_name) < 2:
            validation_errors.append('First name must be at least 2 characters long.')
        elif len(last_name) < 2:
            validation_errors.append('Last name must be at least 2 characters long.')
        elif len(password1) < 7:
            validation_errors.append('Password must be at least 7 characters long.')
        elif password1 != password2:
            validation_errors.append('Passwords do not match.')

        return validation_errors or args

    def user_login_validator(self):
        args = self.parser.parse_args()
        email = args['email']
        password = args['password']
        user = User.query.filter_by(_email=email).first()
        validation_errors = []
        if not user:
            validation_errors.append('Invalid email or password.')
        else:
            if check_password_hash(user._password, password):
                return args
            else:
                validation_errors.append('Invalid email or password.')
        return validation_errors or args

    def password_change_validator(self):
        args = self.parser.parse_args()
        current_password = args['current_password']
        new_password = args['new_password']
        confirm_new_password = args['confirm_new_password']
        validation_errors = []
        if not check_password_hash(current_user._password, current_password):
            validation_errors.append('You must enter the correct password.')
        elif len(new_password) < 7:
            validation_errors.append('Password must be at least 7 characters long.')
        elif new_password != confirm_new_password:
            validation_errors.append('Passwords do not match.')

        return validation_errors or args

    def note_belong_to_user(self, note):
        if note.user_id == current_user.id:
            return True
        return False


class Database():
    _instance = None
    _initialized = False
    _lock = threading.Lock()

    def __new__(cls, db_instance):
        with cls._lock:
            if not cls._instance:
                cls._instance = super(Database, cls).__new__(cls)
            return cls._instance

    def __init__(self, db_instance):
        if not self._initialized:
            self.db = db_instance
            self._initialized = True

    def add_user(self, email, firstname, lastname, password):
        new_user = User()
        new_user.email = email
        new_user.first_name = firstname
        new_user.last_name = lastname
        new_user.password = generate_password_hash(password, method='pbkdf2:sha256:6000')
        self.add_to_database(new_user)
        self.commit_changes()
        return new_user

    def delete_user(self, user):
        self.delete_from_database(user)
        self.commit_changes()

    def update_user_password(self, user, new_passwrod):
        user.password = generate_password_hash(new_passwrod, method='pbkdf2:sha256:6000')
        user.last_password_change = datetime.now()
        self.commit_changes()

    def update_user_state(self, user):
        user._is_active = False if user._is_active else True
        self.commit_changes()

    def update_user_role(self, user, role_id):
        user.role_id = role_id
        self.commit_changes()

    def add_new_note(self, data):
        new_note = Note()
        new_note.data = data
        new_note.user_id = current_user.id
        self.add_to_database(new_note)
        self.commit_changes()
        return new_note

    def update_note(self, note, new_data):
        note.data = new_data
        self.commit_changes()

    def delete_note(self, note):
        self.delete_from_database(note)
        self.commit_changes()

    def add_like(self, note_id):
        new_like = Like()
        new_like.user_id = current_user.id
        new_like.note_id = note_id
        self.add_to_database(new_like)
        self.commit_changes()

    def delete_like(self, existing_like):
        self.delete_from_database(existing_like)
        self.commit_changes()

    def add_to_database(self, new_thing):
        self.db.session.add(new_thing)

    def delete_from_database(self, thing):
        self.db.session.delete(thing)

    def commit_changes(self):
        self.db.session.commit()
