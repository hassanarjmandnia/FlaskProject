from flask_restful import Resource
from flask_login import logout_user, current_user
from .modules import (UserRegistrationManager, UserLoginManager, NoteManager,
                      NoteHandler, RoleManager, UserLikenManager, SuperadminManager,
                      NoteLikeManager, JwtRevoke, PasswordChangeManager,
                      ThereadPoolManager, TestManager, RedisManager)
from website.api.auth import (auth_required, activation_required,
                              access_required, password_change_required)
from website.api.parser_resource_fields import (note_parser, note_resource_fields,
                                                user_login_parser, user_resource_fields,
                                                user_register_parser,
                                                role_parser, role_resource_fields,
                                                likers_resource_fields,
                                                password_change_parser
                                                )
from flask_jwt_extended import (jwt_required, get_jwt_identity, get_jwt,
                                create_access_token)
from website.logger import setup_logger
from flask_caching import Cache
from website import cache

logger = setup_logger('my_logger', 'logger')


class RedisResource(Resource):
    def get(self):
        redis_manager = RedisManager()
        return redis_manager.manager()


class TestResource(Resource):
    def get(self):
        test_manager = TestManager()
        return test_manager.manager()


class ThreadPoolResource(Resource):
    def post(self):
        theread_pool_manager = ThereadPoolManager()
        return theread_pool_manager.manager()


class SuperadminUserResource(Resource):
    @auth_required
    @access_required('superadmin')
    def post(self, id):
        superadmin_manager = SuperadminManager(id, logger)
        return superadmin_manager.update_state_of_user()

    @auth_required
    @access_required('superadmin')
    def patch(self, id):
        superadmin_manager = SuperadminManager(id, logger, role_parser)
        return superadmin_manager.update_role_of_user()

    @auth_required
    @access_required('superadmin')
    def delete(self, id):
        superadmin_manager = SuperadminManager(id, logger)
        return superadmin_manager.delete_user()


class LikeNoteResource(Resource):
    @auth_required
    def get(self, id):
        note_like_manager = NoteLikeManager(id, logger)
        return note_like_manager.show()

    @auth_required
    def post(self, id):
        note_like_manager = NoteLikeManager(id, logger)
        return note_like_manager.add()


class LikeUserResource(Resource):
    @auth_required
    def get(self):
        like_manager = UserLikenManager(logger)
        return like_manager.show()


class RoleResource(Resource):
    @auth_required
    @access_required('admin')
    def post(self):
        role_manager = RoleManager(role_parser, logger)
        return role_manager.add()


class SpecifecNoteResource(Resource):
    @auth_required
    def get(self, id):
        note_manager = NoteManager(id, logger)
        return note_manager.show()

    @auth_required
    def patch(self, id):
        note_manager = NoteManager(id, logger, note_parser)
        return note_manager.update()

    @auth_required
    def delete(self, id):
        note_manager = NoteManager(id, logger)
        return note_manager.delete()


class NoteResource(Resource):
    @auth_required
    @cache.cached(timeout=60, key_prefix='all_notes')  # Cache the result for 1 Minute
    def get(self):
        note_handeler = NoteHandler(logger, cache)
        return note_handeler.show()

    @auth_required
    def post(self):
        note_handeler = NoteHandler(logger, cache, note_parser)
        return note_handeler.add()


class RefreshTokenLogoutResource(Resource):
    @jwt_required(refresh=True)
    def post(self):
        JwtHandeler = JwtRevoke()
        JwtHandeler.add_token_to_blacklist()

        return {'message': 'Refresh token is Revoked.'}, 200


class RefreshTokenResource(Resource):
    @jwt_required(refresh=True)
    def post(self):
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        return {'access_token': new_access_token}, 200


class PasswordChangeResource(Resource):
    @auth_required
    def post(self):
        password_change_manager = PasswordChangeManager(Password_change_parser, logger)
        return password_change_manager.change_password()


class UserLogoutResource(Resource):
    @auth_required
    # @jwt_required()
    def post(self):
        logout_user()
        # JwtHandeler = JwtRevoke()
        # JwtHandeler.add_token_to_blacklist()

        return {'message': 'Logged out.'}, 200


class UserLoginResource(Resource):
    def post(self):
        user_login = UserLoginManager(user_login_parser, logger)
        return user_login.login_user()


class UserRegisterResource(Resource):
    def post(self):
        user_register = UserRegistrationManager(user_register_parser, logger)
        return user_register.register_user()
