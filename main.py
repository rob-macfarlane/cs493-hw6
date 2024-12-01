from flask import Flask, request, jsonify
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

LODGINGS = "lodgings"
BUSINESSES = "businesses"
RESPONSE_400 = {"Error": "The request body is invalid"}
RESPONSE_401 = {"Error": "Unauthorized"}
RESPONSE_403 = {"Error": "You don't have permission on this resource"}
RESPONSE_404 = {"Error": "Not found"}


# Update the values of the following 3 variables
CLIENT_ID = 'x77cabDdJFj4KQaqmA1fUcGZbxJP1X3V'
CLIENT_SECRET = ('oumQBCWCQY5HR9rucWxTOC_'
                 + 'qaPHhVwSHdpL-JvDh65CsEoqGWa1fMkPqKuIEewaP')
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
    return "Success. Homework 5 Robert MacFarlane."


@app.route('/' + BUSINESSES, methods=['POST'])
def create_business():
    '''create a business entity'''
    required_keys = {"name", "street_address", "city", "state",
                     "zip_code", "inspection_score"}
    content = request.get_json()
    if set(content.keys()) != required_keys:
        return {'Error': 'The request body is missing at least one of' +
                ' the required attributes'}, 400
    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
    except AuthError:
        return {'Error': 'Invalid Authentication'}, 401

    new_business = datastore.Entity(key=client.key(BUSINESSES))
    new_business.update({
        'name': content['name'],
        'street_address': content['street_address'],
        'city': content['city'],
        'state': content['state'],
        'zip_code': int(content['zip_code']),
        'inspection_score': int(content['inspection_score']),
        'owner_id': sub
    })
    client.put(new_business)
    new_business['id'] = new_business.key.id
    new_business['self'] = (str(request.base_url)
                            + "/"
                            + str(new_business['id']))
    return new_business, 201


@app.route('/' + BUSINESSES + '/<int:business_id>', methods=['GET'])
def get_business(business_id):
    business_key = client.key(BUSINESSES, business_id)
    business = client.get(key=business_key)
    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
    except AuthError:
        return {'Error': 'Invalid Authentication'}, 401
    if business is None or business['owner_id'] != sub:
        return {"Error": "No business with this business_id exists"}, 403
    else:
        business['id'] = business.key.id
        business['self'] = request.base_url
        return business, 200


@app.route('/' + BUSINESSES, methods=['GET'])
def get_businesses():
    query = client.query(kind=BUSINESSES)

    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
        query = query.add_filter(filter=PropertyFilter('owner_id', '=', sub))
        businesses = list(query.fetch())
        for business in businesses:
            business['id'] = business.key.id
            business['self'] = request.base_url + '/' + str(business['id'])
    except AuthError:
        businesses = list(query.fetch())
        for business in businesses:
            business['id'] = business.key.id
            del business['inspection_score']
            business['self'] = request.base_url + '/' + str(business['id'])
    return businesses


@app.route('/' + BUSINESSES + '/<int:business_id>', methods=['DELETE'])
def delete_business(business_id):
    business_key = client.key(BUSINESSES, business_id)
    business = client.get(key=business_key)
    try:
        payload = verify_jwt(request)
        sub = payload["sub"]
    except AuthError:
        return {'Error': 'Invalid Authentication'}, 401
    if business is None or sub != business['owner_id']:
        return {'Error': 'No business with this business_id exists'}, 403
    else:
        client.delete(key=business_key)
        return ('', 204)


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
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
    return r.text, 200, {'Content-Type': 'application/json'}


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
