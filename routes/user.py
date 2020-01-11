from flask_restful import Resource, reqparse
from models.UserModel import UserModel
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required, jwt_refresh_token_required, get_jwt_identity, get_raw_jwt
)
from blacklist import BlackList


class User(Resource):
    def get(self):
        users = UserModel.get_all_user()
        return users if len(users) >= 1 else "No User In Database"

    # Register user
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument(
            "username",
            type=str,
            required=True,
            help="Required Field"
        ),
        parser.add_argument(
            "email",
            type=str,
            required=True,
            help="Required Field"
        ),
        parser.add_argument(
            "password",
            type=str,
            required=True,
            help="Required Field"
        )

        data = parser.parse_args()
        user_model = UserModel(
            data["username"].lower(),
            data["email"],
            data["password"]
        )
        result = user_model.create_accout()

        return result, result["status"]

    # Login user
    def patch(self):
        parser = reqparse.RequestParser()
        parser.add_argument(
            "username",
            type=str,
            required=True,
            help="Required Field"
        ),
        parser.add_argument(
            "email",
            type=str,
            required=True,
            help="Required Field"
        ),
        parser.add_argument(
            "password",
            type=str,
            required=True,
            help="Required Field"
        )
        data = parser.parse_args()
        user_model = UserModel(
            data["username"].lower(),
            data["email"],
            data["password"]
        )
        result = user_model.login_user()

        if result == True:
            access_token = create_access_token(identity=user_model.username)
            refresh_token = create_refresh_token(identity=user_model.username)

            return {
                "message": "Success",
                "access_token": access_token,
                "refresh_token": refresh_token
            }
        else:
            return {
                "message": "Unable to login user",
                "status": 401
            }, 401

    # delete user if needed
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument(
            "_id",
            type=str,
            required=True,
            help="Required Field"
        )

        data = parser.parse_args()
        result = UserModel.delete_account(data["_id"])
        return result


class Logout(Resource):
    # remove access token
    @jwt_required
    def get(self):
        jwt = get_raw_jwt()["jti"]
        res = BlackList(jwt)
        result = res.add_to_blacklist()

        current_user = get_jwt_identity()
        print(current_user)
        return {
            "message": "Removeed Access Token and {}".format(result),
        }

    # remove refresh token
    @jwt_refresh_token_required
    def delete(self):
        jwt = get_raw_jwt()["jti"]
        res = BlackList(jwt)
        result = res.add_to_blacklist()
        current_user = get_jwt_identity()
        print(current_user)

        return {
            "message": "Removed Refresh Token and {}".format(result)
        }

    # Get new access token from refresh token
    @jwt_refresh_token_required
    def patch(self):
        current_user = get_jwt_identity()
        print(current_user)
        new_access_token = create_access_token(identity=current_user)
        return {
            "result": "Successfully created new Access Token",
            "access_token": new_access_token
        }


class GetUser(Resource):
    @jwt_required
    def get(self):
        current_user = get_jwt_identity()
        return {
            "username": current_user
        }

    def post(self):
        parse = reqparse.RequestParser()
        parse.add_argument(
            'username',
            type=str,
            required=True,
            help="Required Field"
        )
        data = parse.parse_args()
        single_user = UserModel.get_single_user(data["username"])

        error_message = {
            "message": "Unable to get user"
        }
        return single_user if single_user != None else error_message

# create new resource for logout functionality

# add authentication on front-end
# book seats from frontend
# enhance ui in frontend
# focus more on search part and bus detail part
# bus book part will be simple seats layout
