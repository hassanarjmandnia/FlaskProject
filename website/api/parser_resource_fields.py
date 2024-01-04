from flask_restful import reqparse, fields

note_parser = reqparse.RequestParser()
note_parser.add_argument('data', type=str, help='The body of the note is required',
                         required=True, location='form')

note_resource_fields = {
    'id': fields.Integer(attribute='id'),
    'body': fields.String(attribute='data'),
    'date': fields.DateTime(dt_format='iso8601', attribute='date'),
    'user_id': fields.Integer
}

user_login_parser = reqparse.RequestParser()
user_login_parser.add_argument('email', type=str, help='The email used for sign-up',
                               required=True, location='form')
user_login_parser.add_argument('password', type=str, help='Password for login',
                               required=True, location='form')

user_register_parser = user_login_parser.copy()
user_register_parser.add_argument('password2', type=str, help='Confirm your password',
                                  required=True, location='form')
user_register_parser.add_argument('firstname', type=str, help='Your first name',
                                  required=True, location='form')
user_register_parser.add_argument('lastname', type=str, help='Your last name',
                                  required=True, location='form')

user_resource_fields = {
    'id': fields.Integer(attribute='id'),
    'email': fields.String(attribute='email'),
    'first_name': fields.String(attribute='first_name'),
    'last_name': fields.String(attribute='last_name')
}

role_parser = reqparse.RequestParser()
role_parser.add_argument('name', type=str, help='Name of the role you want to add',
                         required=True, location='form')

role_resource_fields = {
    'id': fields.Integer(attribute='id'),
    'name': fields.String(attribute='name')
}

likers_resource_fields = {
    'first_name': fields.String(attribute='first_name'),
    'last_name': fields.String(attribute='last_name')
}

password_change_parser = reqparse.RequestParser()
password_change_parser.add_argument('current_password', type=str, help='Your current password',
                                    required=True, location='form')
password_change_parser.add_argument('new_password', type=str, help='Your new password',
                                    required=True, location='form')
password_change_parser.add_argument('confirm_new_password', type=str, help='Confirm your new password',
                                    required=True, location='form')
