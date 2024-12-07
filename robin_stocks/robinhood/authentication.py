"""Contains all functions for the purpose of logging in and out to Robinhood."""
import datetime
import getpass
import json
import os
import pickle
import random
import uuid
import zlib
from google.cloud import datastore


from robin_stocks.robinhood.helper import *
import robin_stocks.robinhood.crypto as rh_crypto
from robin_stocks.robinhood.urls import *

def generate_device_token():
    """This function will generate a token used when loggin on.

    :returns: A string representing the token.

    """
    rands = []
    for i in range(0, 16):
        r = random.random()
        rand = 4294967296.0 * r
        rands.append((int(rand) >> ((3 & i) << 3)) & 255)

    hexa = []
    for i in range(0, 256):
        hexa.append(str(hex(i+256)).lstrip("0x").rstrip("L")[1:])

    id = ""
    for i in range(0, 16):
        id += hexa[rands[i]]

        if (i == 3) or (i == 5) or (i == 7) or (i == 9):
            id += "-"

    return(id)

def pathfind_user_machine(device_id, workflow_id):
    """This function will post to the challenge url.

    :param challenge_id: The challenge id.
    :type challenge_id: str
    :param sms_code: The sms code.
    :type sms_code: str
    :returns:  The response from requests.

    """
    url = 'https://api.robinhood.com/pathfinder/user_machine/'
    payload = {"device_id":device_id,"flow":"suv","input":{"workflow_id":workflow_id}}
    return(request_post(url, payload,json=True))

def pathfind_user_view_post(user_id):
    payload = {"sequence":0,"user_input":{"status":"continue"}}
    url = f'https://api.robinhood.com/pathfinder/inquiries/{user_id}/user_view/'
    return (request_post(url, payload, json=True))
def pathfind_user_view(user_id):
    """This function will post to the challenge url.

    :param challenge_id: The challenge id.
    :type challenge_id: str
    :param sms_code: The sms code.
    :type sms_code: str
    :returns:  The response from requests.

    """
    url = f'https://api.robinhood.com/pathfinder/inquiries/{user_id}/user_view/'
    return(request_get(url))

def check_prompt_approved(user_id):
    """This function will post to the challenge url.

    :param challenge_id: The challenge id.
    :type challenge_id: str
    :param sms_code: The sms code.
    :type sms_code: str
    :returns:  The response from requests.

    """
    url = f'https://api.robinhood.com/push/{user_id}/get_prompts_status/'
    return(request_get(url))
def respond_to_challenge(challenge_id, sms_code):
    """This function will post to the challenge url.

    :param challenge_id: The challenge id.
    :type challenge_id: str
    :param sms_code: The sms code.
    :type sms_code: str
    :returns:  The response from requests.

    """
    url = challenge_url(challenge_id)
    payload = {
        'response': sms_code
    }
    return(request_post(url, payload))



def handle_mfa_challenge(payload, url, dsClient, pickle_name, mfa_token):
    objct = dict()
    objct['success'] = False
    payload['mfa_code'] = mfa_token
    res = request_post(url, payload, jsonify_data=False)
    if (res.status_code != 200):
        return objct
    data = res.json()
    if 'access_token' in data:
        token = '{0} {1}'.format(data['token_type'], data['access_token'])
        update_session('Authorization', token)
        set_login_state(True)
        data['detail'] = "logged in with brand new authentication code."

        oauth_obj = {'token_type': data['token_type'],
                     'access_token': data['access_token'],
                     'refresh_token': data['refresh_token'],
                     'device_token': payload['device_token']}
        key = dsClient.key('aaf-crypto-bot-sessions', pickle_name)
        entity = datastore.Entity(key=key)
        new_entity = dict()
        new_entity['session'] = zlib.compress(json.dumps(oauth_obj).encode('utf-8'), 9)
        new_entity['user'] = pickle_name
        new_entity['expires_on'] = datetime.datetime.now() + datetime.timedelta(days=8)
        new_entity['expired'] = False

        acct_id = rh_crypto.load_crypto_profile(info="id")
        new_entity['rh_crypto_set_up'] = False
        if acct_id is not None:
            new_entity['rh_crypto_set_up'] = True

        entity.update(new_entity)
        dsClient.put(entity)
        objct['success'] = True
    return objct


def handle_verification_challenge(challenge_id, url, payload, dsClient, pickle_name, sms_code, user_view_id, prompt_approved):
    objct = dict()
    objct['success'] = False
    res = None
    if prompt_approved:
        res = check_prompt_approved(challenge_id)
        print('response from challenge')
        print(res)
        print("response from challenge")
        if res['challenge_status'] != 'validated':
            return objct

    else:
        res = respond_to_challenge(challenge_id, sms_code)
        print('response from challenge')
        print(res)
        print("response from challenge")

    user_view = pathfind_user_view_post(user_view_id)
    print("YAYYY")
    print(user_view)
    print("YAYYY")
    data = request_post(url, payload)
    print("this is the data response")
    print(data)
    print("THIS IS THE DATA RESPONSE FROM")

    if 'access_token' in data:
        token = '{0} {1}'.format(data['token_type'], data['access_token'])
        update_session('Authorization', token)
        set_login_state(True)
        data['detail'] = "logged in with brand new authentication code."

        oauth_obj = {'token_type': data['token_type'],
                     'access_token': data['access_token'],
                     'refresh_token': data['refresh_token'],
                     'device_token': payload['device_token']}
        key = dsClient.key('aaf-crypto-bot-sessions', pickle_name)
        entity = datastore.Entity(key=key)
        new_entity = dict()
        new_entity['session'] = zlib.compress(json.dumps(oauth_obj).encode('utf-8'), 9)
        new_entity['user'] = pickle_name
        new_entity['expires_on'] = datetime.datetime.now() + datetime.timedelta(days=8)
        new_entity['expired'] = False

        acct_id = rh_crypto.load_crypto_profile(info="id")
        new_entity['rh_crypto_set_up'] = False
        if acct_id is not None:
            new_entity['rh_crypto_set_up'] = True
        entity.update(new_entity)
        dsClient.put(entity)
        objct['success'] = True
    return  objct

def handle_sms_challenge(challenge_id,url , payload, dsClient, pickle_name, sms_code):
    sms_code = sms_code
    res = respond_to_challenge(challenge_id, sms_code)
    objct = dict()
    objct['success'] = False
    if 'challenge' in res:
        objct['remaining_attempts'] = res['challenge']['remaining_attempts']
        return objct
    update_session(
        'X-ROBINHOOD-CHALLENGE-RESPONSE-ID', challenge_id)
    data = request_post(url, payload)
    if 'access_token' in data:
        token = '{0} {1}'.format(data['token_type'], data['access_token'])
        update_session('Authorization', token)
        set_login_state(True)
        data['detail'] = "logged in with brand new authentication code."

        oauth_obj = {'token_type': data['token_type'],
                     'access_token': data['access_token'],
                     'refresh_token': data['refresh_token'],
                     'device_token': payload['device_token']}
        key = dsClient.key('aaf-crypto-bot-sessions', pickle_name)
        entity = datastore.Entity(key=key)
        new_entity = dict()
        new_entity['session'] = zlib.compress(json.dumps(oauth_obj).encode('utf-8'), 9)
        new_entity['user'] = pickle_name
        new_entity['expires_on'] = datetime.datetime.now() + datetime.timedelta(days=8)
        new_entity['expired'] = False

        acct_id = rh_crypto.load_crypto_profile(info="id")
        new_entity['rh_crypto_set_up'] = False
        if acct_id is not None:
            new_entity['rh_crypto_set_up'] = True
        entity.update(new_entity)
        dsClient.put(entity)
        objct['success'] = True
    return  objct

def crypto_api_login(publicKey, privateKey, apiKey):
    set_api_state(True, publicKey, privateKey, apiKey)

def create_session_on_db(username=None, password=None, expiresIn=691200, scope='internal', by_sms=True, dsClient=None, mfa_code=None, pickle_name=None):
    """This function will effectively log the user into robinhood by getting an
    authentication token and saving it to the session header. By default, it
    will store the authentication token in a pickle file and load that value
    on subsequent logins.

    :param username: The username for your robinhood account, usually your email.
        Not required if credentials are already cached and valid.
    :type username: Optional[str]
    :param password: The password for your robinhood account. Not required if
        credentials are already cached and valid.
    :type password: Optional[str]
    :param expiresIn: The time until your login session expires. This is in seconds.
    :type expiresIn: Optional[int]
    :param scope: Specifies the scope of the authentication.
    :type scope: Optional[str]
    :param by_sms: Specifies whether to send an email(False) or an sms(True)
    :type by_sms: Optional[boolean]
    :param store_session: Specifies whether to save the log in authorization
        for future log ins.
    :type store_session: Optional[boolean]
    :param mfa_code: MFA token if enabled.
    :type mfa_code: Optional[str]
    :param pickle_name: Allows users to name Pickle token file in order to switch
        between different accounts without having to re-login every time.
    :returns:  A dictionary with log in information. The 'access_token' keyword contains the access token, and the 'detail' keyword \
    contains information on whether the access token was generated or loaded from pickle file.

    """
    device_token = generate_device_token()
    # Challenge type is used if not logging in with two-factor authentication.
    if by_sms:
        challenge_type = "sms"
    else:
        challenge_type = "email"

    url = login_url()
    payload = {
        'client_id': 'c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS',
        'expires_in': expiresIn,
        'grant_type': 'password',
        'password': password,
        'scope': scope,
        'username': username,
        'challenge_type': challenge_type,
        'device_token': device_token,
        "token_request_path": "/login",
        "create_read_only_secondary_token": False,
        "request_id": str(uuid.uuid4())
    }

    if mfa_code:
        payload['mfa_code'] = mfa_code

    data = request_post(url, payload)
    # Handle case where mfa or challenge is required.
    if data:
        if 'mfa_required' in data:
            resp_obj = {'verification_type': 'mfa_required', 'payload' : payload, 'url': url}
            return resp_obj
        elif 'verification_workflow' in data:
            challenge_id = data['verification_workflow']['id']
            resp = pathfind_user_machine(payload['device_token'], challenge_id)

            user_view = pathfind_user_view(resp['id'])
            resp_obj = {'verification_type': 'challenge', 'user_view_id': resp['id'] ,'challenge_id': user_view['context']['sheriff_challenge']['id'], 'payload': payload, 'url': url}
            return resp_obj

        elif 'challenge' in data:
            challenge_id = data['challenge']['id']
            resp_obj = {'verification_type': 'challenge', 'challenge_id' :challenge_id, 'payload' : payload, 'url': url}
            return resp_obj
        # Update Session data with authorization or raise exception with the information present in data.
        if 'access_token' in data:
            token = '{0} {1}'.format(data['token_type'], data['access_token'])
            update_session('Authorization', token)
            set_login_state(True)
            data['detail'] = "logged in with brand new authentication code."

            oauth_obj = {'token_type': data['token_type'],
                         'access_token': data['access_token'],
                         'refresh_token': data['refresh_token'],
                         'device_token': payload['device_token']}
            key = dsClient.key('aaf-crypto-bot-sessions', pickle_name)
            entity = datastore.Entity(key=key)
            new_entity = dict()
            new_entity['user'] = pickle_name
            new_entity['expires_on'] = datetime.datetime.now() + datetime.timedelta(days=8)
            new_entity['expired'] = False
            new_entity['session'] = zlib.compress(json.dumps(oauth_obj).encode('utf-8'), 9)
            entity.update(new_entity)
            dsClient.put(entity)

        else:
            raise Exception(data['detail'])
    else:
        raise Exception('Error: Trouble connecting to robinhood API. Check internet connection.')
    return(data)


def login_fom_db(username=None, password=None, expiresIn=691200, scope='internal', by_sms=True, store_session=True,
          mfa_code=None, pickle_name="", dsClient=None):
    """This function will effectively log the user into robinhood by getting an
    authentication token and saving it to the session header. By default, it
    will store the authentication token in a pickle file and load that value
    on subsequent logins.

    :param username: The username for your robinhood account, usually your email.
        Not required if credentials are already cached and valid.
    :type username: Optional[str]
    :param password: The password for your robinhood account. Not required if
        credentials are already cached and valid.
    :type password: Optional[str]
    :param expiresIn: The time until your login session expires. This is in seconds.
    :type expiresIn: Optional[int]
    :param scope: Specifies the scope of the authentication.
    :type scope: Optional[str]
    :param by_sms: Specifies whether to send an email(False) or an sms(True)
    :type by_sms: Optional[boolean]
    :param store_session: Specifies whether to save the log in authorization
        for future log ins.
    :type store_session: Optional[boolean]
    :param mfa_code: MFA token if enabled.
    :type mfa_code: Optional[str]
    :param pickle_name: Allows users to name Pickle token file in order to switch
        between different accounts without having to re-login every time.
    :returns:  A dictionary with log in information. The 'access_token' keyword contains the access token, and the 'detail' keyword \
    contains information on whether the access token was generated or loaded from pickle file.

    """
    device_token = generate_device_token()
    # Challenge type is used if not logging in with two-factor authentication.
    if by_sms:
        challenge_type = "sms"
    else:
        challenge_type = "email"

    url = login_url()
    payload = {
        'client_id': 'c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS',
        'expires_in': expiresIn,
        'grant_type': 'password',
        'password': password,
        'scope': scope,
        'username': username,
        'challenge_type': challenge_type,
        'device_token': device_token,
        "token_request_path": "/login",
        "create_read_only_secondary_token": False,
        "request_id" : str( uuid.uuid4())
    }

    key = dsClient.key('aaf-crypto-bot-sessions', pickle_name)
    entity = dsClient.get(key)

    if entity is not None and 'expired' in entity and entity['expired']:
        raise Exception('SESSION EXPIRED')

    # If authentication has been stored in pickle file then load it. Stops login server from being pinged so much.
    try:

        if entity is not None:

            pickle_data = json.loads(zlib.decompress(entity['session']).decode('utf-8'))
            access_token = pickle_data['access_token']
            token_type = pickle_data['token_type']
            refresh_token = pickle_data['refresh_token']
            # Set device_token to be the original device token when first logged in.
            pickle_device_token = pickle_data['device_token']
            payload['device_token'] = pickle_device_token
            # Set login status to True in order to try and get account info.
            set_login_state(True)
            update_session(
                'Authorization', '{0} {1}'.format(token_type, access_token))
            # Try to load account profile to check that authorization token is still valid.
            res = request_get(
                positions_url(), 'pagination', {'nonzero': 'true'}, jsonify_data=False)
            # Raises exception is response code is not 200.
            res.raise_for_status()
            return ({'access_token': access_token, 'token_type': token_type,
                     'expires_in': expiresIn, 'scope': scope,
                     'backup_code': None, 'refresh_token': refresh_token})
    except:
        print(
            "ERROR: There was an issue loading pickle file. Authentication may be expired - logging in normally.",
            file=get_output())
        set_login_state(False)
        update_session('Authorization', None)
    if mfa_code:
        payload['mfa_code'] = mfa_code
    else:
        if entity is not None:
            new_entity = dict()
            # iterate through the entity to take over all existing property values
            for prop in entity:
                new_entity[prop] = entity[prop]

            new_entity['expired'] = True
            entity.update(new_entity)
            dsClient.put(entity)

        raise Exception('SESSION EXPIRED')
    data = request_post(url, payload)
    # Handle case where mfa or challenge is required.
    if data:
        # Update Session data with authorization or raise exception with the information present in data.
        if 'access_token' in data:
            token = '{0} {1}'.format(data['token_type'], data['access_token'])
            update_session('Authorization', token)
            set_login_state(True)
            data['detail'] = "logged in with brand new authentication code."
            oauth_obj = {'token_type': data['token_type'],
                                 'access_token': data['access_token'],
                                 'refresh_token': data['refresh_token'],
                                 'device_token': payload['device_token']}

            entity = datastore.Entity(key=key)
            new_entity = dict()
            new_entity['session'] = zlib.compress(json.dumps(oauth_obj).encode('utf-8'), 9)
            new_entity['user'] = pickle_name
            new_entity['expires_on'] = datetime.datetime.now() + datetime.timedelta(days=8)
            entity.update(new_entity)
            dsClient.put(entity)
        else:
            raise Exception(data['detail'])
    else:
        raise Exception('Error: Trouble connecting to robinhood API. Check internet connection.')
    return (data)


def login(username=None, password=None, expiresIn=691200, scope='internal', by_sms=True, store_session=True, mfa_code=None, pickle_name=""):
    """This function will effectively log the user into robinhood by getting an
    authentication token and saving it to the session header. By default, it
    will store the authentication token in a pickle file and load that value
    on subsequent logins.

    :param username: The username for your robinhood account, usually your email.
        Not required if credentials are already cached and valid.
    :type username: Optional[str]
    :param password: The password for your robinhood account. Not required if
        credentials are already cached and valid.
    :type password: Optional[str]
    :param expiresIn: The time until your login session expires. This is in seconds.
    :type expiresIn: Optional[int]
    :param scope: Specifies the scope of the authentication.
    :type scope: Optional[str]
    :param by_sms: Specifies whether to send an email(False) or an sms(True)
    :type by_sms: Optional[boolean]
    :param store_session: Specifies whether to save the log in authorization
        for future log ins.
    :type store_session: Optional[boolean]
    :param mfa_code: MFA token if enabled.
    :type mfa_code: Optional[str]
    :param pickle_name: Allows users to name Pickle token file in order to switch
        between different accounts without having to re-login every time.
    :returns:  A dictionary with log in information. The 'access_token' keyword contains the access token, and the 'detail' keyword \
    contains information on whether the access token was generated or loaded from pickle file.

    """
    device_token = generate_device_token()
    home_dir = os.path.expanduser("~")
    data_dir = os.path.join(home_dir, ".tokens")
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    creds_file = "robinhood" + pickle_name + ".pickle"
    pickle_path = os.path.join(data_dir, creds_file)
    # Challenge type is used if not logging in with two-factor authentication.
    if by_sms:
        challenge_type = "sms"
    else:
        challenge_type = "email"

    url = login_url()
    payload = {
        'client_id': 'c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS',
        'expires_in': expiresIn,
        'grant_type': 'password',
        'password': password,
        'scope': scope,
        'username': username,
        'challenge_type': challenge_type,
        'device_token': device_token
    }

    if mfa_code:
        payload['mfa_code'] = mfa_code

    # If authentication has been stored in pickle file then load it. Stops login server from being pinged so much.
    if os.path.isfile(pickle_path):
        # If store_session has been set to false then delete the pickle file, otherwise try to load it.
        # Loading pickle file will fail if the acess_token has expired.
        if store_session:
            try:
                with open(pickle_path, 'rb') as f:
                    pickle_data = pickle.load(f)
                    access_token = pickle_data['access_token']
                    token_type = pickle_data['token_type']
                    refresh_token = pickle_data['refresh_token']
                    # Set device_token to be the original device token when first logged in.
                    pickle_device_token = pickle_data['device_token']
                    payload['device_token'] = pickle_device_token
                    # Set login status to True in order to try and get account info.
                    set_login_state(True)
                    update_session(
                        'Authorization', '{0} {1}'.format(token_type, access_token))
                    # Try to load account profile to check that authorization token is still valid.
                    res = request_get(
                        positions_url(), 'pagination', {'nonzero': 'true'}, jsonify_data=False)
                    # Raises exception is response code is not 200.
                    res.raise_for_status()
                    return({'access_token': access_token, 'token_type': token_type,
                            'expires_in': expiresIn, 'scope': scope, 'detail': 'logged in using authentication in {0}'.format(creds_file),
                            'backup_code': None, 'refresh_token': refresh_token})
            except:
                print(
                    "ERROR: There was an issue loading pickle file. Authentication may be expired - logging in normally.", file=get_output())
                set_login_state(False)
                update_session('Authorization', None)
        else:
            os.remove(pickle_path)

    # Try to log in normally.
    if not username:
        username = input("Robinhood username: ")
        payload['username'] = username

    if not password:
        password = getpass.getpass("Robinhood password: ")
        payload['password'] = password

    data = request_post(url, payload)
    # Handle case where mfa or challenge is required.
    if data:
        if 'mfa_required' in data:
            mfa_token = input("Please type in the MFA code: ")
            payload['mfa_code'] = mfa_token
            res = request_post(url, payload, jsonify_data=False)
            while (res.status_code != 200):
                mfa_token = input(
                    "That MFA code was not correct. Please type in another MFA code: ")
                payload['mfa_code'] = mfa_token
                res = request_post(url, payload, jsonify_data=False)
            data = res.json()
        elif 'challenge' in data:
            challenge_id = data['challenge']['id']
            sms_code = input('Enter Robinhood code for validation: ')
            res = respond_to_challenge(challenge_id, sms_code)
            while 'challenge' in res and res['challenge']['remaining_attempts'] > 0:
                sms_code = input('That code was not correct. {0} tries remaining. Please type in another code: '.format(
                    res['challenge']['remaining_attempts']))
                res = respond_to_challenge(challenge_id, sms_code)
            update_session(
                'X-ROBINHOOD-CHALLENGE-RESPONSE-ID', challenge_id)
            data = request_post(url, payload)
        # Update Session data with authorization or raise exception with the information present in data.
        if 'access_token' in data:
            token = '{0} {1}'.format(data['token_type'], data['access_token'])
            update_session('Authorization', token)
            set_login_state(True)
            data['detail'] = "logged in with brand new authentication code."
            if store_session:
                with open(pickle_path, 'wb') as f:
                    pickle.dump({'token_type': data['token_type'],
                                 'access_token': data['access_token'],
                                 'refresh_token': data['refresh_token'],
                                 'device_token': payload['device_token']}, f)
        else:
            raise Exception(data['detail'])
    else:
        raise Exception('Error: Trouble connecting to robinhood API. Check internet connection.')
    return(data)


@login_required
def logout():
    """Removes authorization from the session header.

    :returns: None

    """
    update_session('Authorization', None)
    set_api_state(False,None,None, None)
