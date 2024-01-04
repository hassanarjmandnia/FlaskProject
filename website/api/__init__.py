from flask_restful import Api
from .api import (NoteResource, SpecifecNoteResource,
                  UserLoginResource, UserLogoutResource, UserRegisterResource,
                  RoleResource,
                  LikeNoteResource,
                  LikeUserResource,
                  SuperadminUserResource,
                  RefreshTokenResource, RefreshTokenLogoutResource,
                  PasswordChangeResource,
                  ThreadPoolResource,
                  TestResource, RedisResource
                  )

api = Api()

api.add_resource(RedisResource, '/Redis')
api.add_resource(TestResource, '/Test')
api.add_resource(ThreadPoolResource, '/Thread')

api.add_resource(NoteResource, '/Note')
api.add_resource(SpecifecNoteResource, '/Note-specifec/<int:id>')
api.add_resource(UserLoginResource, '/User')
api.add_resource(UserLogoutResource, '/User-logout')
api.add_resource(UserRegisterResource, '/User-register')
api.add_resource(RoleResource, '/Role')
api.add_resource(LikeNoteResource, '/Like/<int:id>')
api.add_resource(LikeUserResource, '/Like')
api.add_resource(SuperadminUserResource, '/Superadmin-user/<int:id>')
api.add_resource(RefreshTokenResource, '/RefreshToken')
api.add_resource(RefreshTokenLogoutResource, '/User-RefreshToken-logout')
api.add_resource(PasswordChangeResource, '/Password-change')
