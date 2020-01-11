from flask import Flask
from flask_restful import Api
from flask_pymongo import PyMongo
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from routes import bus
from routes import route
from routes import reservation
from routes import user

from blacklist import BlackList

app = Flask(__name__)
api = Api(app)
CORS(app)

app.config["MONGO_URI"] = "mongodb://localhost:27017/ticket"
app.config["JWT_SECRET_KEY"] = "secret_key"

db = PyMongo(app)
jwt = JWTManager(app)


app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']


@jwt.token_in_blacklist_loader
def check_if_token_in_blacklist(decrypted_token):
    jti = decrypted_token['jti']
    jti_class = BlackList(jti)
    return jti_class.filter_blacklist()


@app.route("/")
def index():
    return "Hello world"


api.add_resource(bus.Bus, "/admin/bus")
api.add_resource(route.Route, "/admin/route")

api.add_resource(reservation.Reservation, "/book/seats")
api.add_resource(user.User, "/auth")
api.add_resource(user.Logout, '/auth/logout')

api.add_resource(user.GetUser, "/get/user")


if __name__ == "__main__":
    app.run(port=4000)
