from flask import Flask, request, jsonify, send_file
from google.cloud import datastore
from google.cloud.datastore.query import PropertyFilter
from google.cloud import storage
import io

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
# app.secret_key = 'SECRET_KEY'

client = datastore.Client()

AVATAR_BUCKET = 'cs493-hw6_macfarlane'
COURSES = "courses"
USERS = "users"
RESPONSE_400 = {"Error": "The request body is invalid"}
RESPONSE_401 = {"Error": "Unauthorized"}
RESPONSE_403 = {"Error": "You don't have permission on this resource"}
RESPONSE_404 = {"Error": "Not found"}


# Update the values of the following 3 variables
CLIENT_ID = 'vPC7Jv3JIrKKbqY1EmJgHgfYlKYWmZIH'
CLIENT_SECRET = ('L_z1zRm6qB3uojVWm_tztzjbPkmqvOp'
                 + 'NPwjOPZsBE0CHHAHyslfKZx86h5eUdoTW')
DOMAIN = 'hw5-cs493-macfarlane.us.auth0.com'
# For example
# DOMAIN = '493-24-spring.us.auth0.com'
# Note: don't include the protocol in the value of the variable DOMAIN

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                         "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN + "/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description": "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Success. CS493 Portfolio Project - Robert MacFarlane."


@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_user(user_id):
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    keys = {"avatar_url", "courses", "id", "role", "sub"}
    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
        role = get_user_with_jwt(sub)
    except AuthError:
        return RESPONSE_401, 401
    if user is None or (user['sub'] != sub and role != 'admin'):
        return RESPONSE_403, 403
    else:
        user['id'] = user.key.id
        user = {
            key: value
            for key, value in user.items()
            if key in keys and value
            }
        return user, 200


def get_user_with_jwt(sub):
    query = client.query(kind=USERS)
    query = query.add_filter(filter=PropertyFilter('sub', '=', sub))
    users = list(query.fetch())
    for user in users:
        user['id'] = user.key.id
    return users[0]


@app.route('/' + USERS, methods=['GET'])
def get_users():
    query = client.query(kind=USERS)
    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
        role = get_user_with_jwt(sub)['role']
        if role != 'admin':
            return RESPONSE_403, 403
        users = list(query.fetch())
        for user in users:
            user['id'] = user.key.id
    except AuthError:
        return RESPONSE_401, 401
    return users


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():
    required_keys = {"username", "password"}
    content = request.get_json()
    if set(content.keys()) != required_keys:
        return RESPONSE_400, 400
    username = content["username"]
    password = content["password"]
    body = {'grant_type': 'password',
            'username': username,
            'password': password,
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET
            }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    if r.status_code != 200:
        return RESPONSE_401, 401
    response = r.json()
    token = response["id_token"]
    return {"token": token}, 200


@app.route('/' + USERS + '/<int:user_id>/avatar', methods=['POST'])
def add_avatar(user_id):
    if 'file' not in request.files:
        return RESPONSE_400, 400

    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)
    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
        user_based_on_jwt = get_user_with_jwt(sub)
        if user_based_on_jwt['id'] != user_id:
            return RESPONSE_403, 403
        file_obj = request.files['file']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        blob = bucket.blob(file_obj.filename)
        file_obj.seek(0)
        blob.upload_from_file(file_obj)
        url = request.base_url
        user.update({
            'avatar_file': str(file_obj.filename),
            'avatar_url': url
        })
        client.put(user)
        return ({'avatar_url': url}, 200)
    except AuthError:
        return RESPONSE_401, 401


@app.route('/' + USERS + '/<int:user_id>/avatar', methods=['GET'])
def get_avatar(user_id):

    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
        user_based_on_jwt = get_user_with_jwt(sub)
        if user_based_on_jwt['id'] != user_id:
            return RESPONSE_403, 403
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if 'avatar_file' not in user.keys() or user['avatar_file'] == "":
            return RESPONSE_404, 404
        file_name = user['avatar_file']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        blob = bucket.blob(file_name)
        file_obj = io.BytesIO()
        blob.download_to_file(file_obj)
        file_obj.seek(0)
        return send_file(file_obj, mimetype='image/x-png',
                         download_name=file_name)
    except AuthError:
        return RESPONSE_401, 401


@app.route('/' + USERS + '/<int:user_id>/avatar', methods=['DELETE'])
def delete_avatar(user_id):
    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
        user_based_on_jwt = get_user_with_jwt(sub)
        if user_based_on_jwt['id'] != user_id:
            return RESPONSE_403, 403
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if 'avatar_file' not in user.keys() or user['avatar_file'] == "":
            return RESPONSE_404, 404
        file_name = user['avatar_file']
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)
        blob = bucket.blob(file_name)
        # Delete the file from Cloud Storage
        blob.delete()
        user.update({
            'avatar_file': "",
            'avatar_url': ""
        })
        client.put(user)
        return '', 204
    except AuthError:
        return RESPONSE_401, 401


def get_role(id):
    user_key = client.key(USERS, id)
    user = client.get(key=user_key)
    return user['role']


@app.route('/' + COURSES, methods=['POST'])
def create_course():
    '''create a user entity'''
    required_keys = {"subject", "number", "title", "term", "instructor_id"}
    content = request.get_json()

    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
        role = get_user_with_jwt(sub)['role']
        if role != 'admin':
            return RESPONSE_403, 403
    except AuthError:
        return RESPONSE_401, 401

    if set(content.keys()) != required_keys:
        return RESPONSE_400, 400

    instructor_id = content['instructor_id']
    role = get_role(instructor_id)
    if role != 'instructor':
        return RESPONSE_400, 400
    new_course = datastore.Entity(key=client.key(COURSES))
    new_course.update({
        'subject': content['subject'],
        'number': int(content['number']),
        'title': content['title'],
        'term': content['term'],
        'instructor_id': int(content['instructor_id'])
    })
    client.put(new_course)
    new_course['id'] = new_course.key.id
    new_course['self'] = (str(request.base_url) + "/" + str(new_course['id']))
    return new_course, 201


@app.route('/' + COURSES, methods=['GET'])
def get_all_courses():
    x = int(request.args.get('limit', 3))
    y = int(request.args.get('offset', 0))

    query = client.query(kind=COURSES)
    query.order = ['subject']
    course_iterator = query.fetch(limit=x, offset=y)
    pages = course_iterator.pages
    courses = list(next(pages))

    for course in courses:
        course['id'] = course.key.id
        course['self'] = request.base_url + "/" + str(course.key.id)
    url = request.base_url + "?limit=3&offset=" + str(y+x)
    res = {
        "courses": courses,
        "next": url
    }

    return res


@app.route('/' + COURSES + '/<int:course_id>')
def get_course(course_id):
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)

    if course is None:
        return RESPONSE_404, 404

    course['id'] = course_id
    course['self'] = request.base_url

    return course, 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
