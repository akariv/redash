import logging
import requests
import json
from flask import redirect, url_for, Blueprint, request
from redash.authentication.google_oauth import create_and_login_user
from redash.authentication.org_resolving import current_org
from redash import settings

logger = logging.getLogger('jwt_auth')

blueprint = Blueprint('jwt_auth', __name__)

@blueprint.route("/jwt/login")
def login():
    next_path = request.args.get('next')
    jwt = request.args.get('jwt')

    if not settings.JWT_LOGIN_ENABLED:
        logger.error("Cannot use jwt for login without being enabled in settings")
        return redirect(url_for('redash.index', next=next_path))

    auth_server = settings.JWT_AUTH_SERVER
    if not auth_server:
        logger.error("Cannot use jwt for login when there's no auth server")
        return redirect(url_for('redash.index', next=next_path))

    try:
        logger.error('JWT=={}'.format(jwt))
        profile = requests.get(auth_server, data={'jwt':jwt}).json()
        if profile is not None and profile.get('authenticated') is True:
            profile = profile['profile']
            create_and_login_user(current_org, profile['name'], profile['email'])
        else:
            logger.warning("Failed to verify user with jwt {}".format(jwt))
    except Exception as e:
        logger.error("Failed to verify jwt: {}".format(e))

    return redirect(next_path or url_for('redash.index'), code=302)
