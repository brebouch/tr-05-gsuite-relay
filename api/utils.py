from jwt import PyJWKClient
import jwt as pyjwt
from authlib.jose import jwt
from authlib.jose.errors import DecodeError, BadSignatureError
from flask import request, current_app, jsonify

from api.errors import AuthorizationError, InvalidArgumentError


def get_auth_token():
    """
    Parse and validate incoming request Authorization header.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """
    expected_errors = {
        KeyError: 'Authorization header is missing',
        AssertionError: 'Wrong authorization type'
    }
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return token
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_jwt():
    """
    Parse the incoming request's Authorization Bearer JWT for some credentials.
    Validate its signature against the application's secret key.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    expected_errors = {
        KeyError: 'Wrong JWT payload structure',
        TypeError: '<SECRET_KEY> is missing',
        BadSignatureError: 'Failed to decode JWT with provided key',
        DecodeError: 'Wrong JWT structure'
    }
    token = get_auth_token()
    try:
        jwks_host = pyjwt.decode(token, options={'verify_signature': False})
        svc_act = {
          "type": "service_account",
          "project_id": jwks_host['project_id'],
          "private_key_id": jwks_host['private_key_id'],
          "private_key": jwks_host['private_key'].replace('\\n', '\n'),
          "client_email": jwks_host['client_email'],
          "client_id": jwks_host['client_id'],
          "auth_uri": jwks_host['auth_uri'],
          "token_uri": jwks_host['token_uri'],
          "auth_provider_x509_cert_url": jwks_host['auth_provider_x509_cert_url'],
          "client_x509_cert_url": jwks_host['client_x509_cert_url'],
          "universe_domain": jwks_host['universe_domain']
        }
        return {'service_account': svc_act, 'delegated_email': jwks_host['delegated_email'],
                'internal_domains': jwks_host['internal_domains']}
    except tuple(expected_errors) as error:
        raise AuthorizationError(expected_errors[error.__class__])


def get_json(schema):
    """
    Parse the incoming request's data as JSON.
    Validate it against the specified schema.

    NOTE. This function is just an example of how one can read and check
    anything before passing to an API endpoint, and thus it may be modified in
    any way, replaced by another function, or even removed from the module.
    """

    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data

def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_errors(data):
    return jsonify({'errors': [data]})
