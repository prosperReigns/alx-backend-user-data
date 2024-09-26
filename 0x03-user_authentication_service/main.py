#!/usr/bin/env python3
"""
Main file
"""
from auth import Auth
import requests


AUTH = Auth()


def register_user(email: str, password: str) -> None:
    """Test /users end-point"""
    payload = {'email': email, 'password': password}
    r = requests.post('http://localhost:5000/users', data=payload)
    # Check the response status code
    if r.status_code == 200:
        assert r.json() == {"email": email, "message": "user created"}
    elif r.status_code == 400:
        assert r.json() == {"message": "email already registered"}


def log_in_wrong_password(email: str, password: str) -> None:
    """Test /sessions end-point"""
    payload = {'email': email, 'password': password}
    r = requests.post('http://localhost:5000/sessions', data=payload)
    assert r.status_code == 401


def log_in(email: str, password: str) -> str:
    """Test /sessions end-point"""
    payload = {'email': email, 'password': password}
    r = requests.post('http://localhost:5000/sessions', data=payload)

    # Assert that the status code is 200 for successful login
    assert r.status_code == 200

    # Assert that the response JSON is as expected
    assert r.json() == {"email": email, "message": "logged in"}

    # Assert that 'Set-Cookie' is present in the headers
    assert 'Set-Cookie' in r.headers

    # If assertions pass, extract and return the session ID from the cookies
    return r.cookies.get('session_id')


def profile_unlogged() -> None:
    """Test profile not yet logged in"""
    r = requests.get('http://localhost:5000/profile')
    assert r.status_code == 403
    assert 'Set-Cookie' not in r.headers


def profile_logged(session_id: str) -> None:
    """Test profile logged in"""
    cookies = {'session_id': session_id}
    r = requests.get('http://localhost:5000/profile', cookies=cookies)

    # Fetch the user associated with the session_id
    user = AUTH.get_user_from_session_id(session_id)

    assert r.status_code == 200
    assert r.json() == {"email": "guillaume@holberton.io"}


def log_out(session_id: str) -> None:
    """Test log out"""
    cookies = {'session_id': session_id}
    r = requests.delete('http://localhost:5000/sessions', cookies=cookies)

    assert r.status_code == 200

    # Fetch the user associated with the session_id
    user = AUTH.get_user_from_session_id(session_id)

    assert user is None
    assert len(r.history) > 0


def reset_password_token(email: str) -> str:
    "Test reset password token"""
    payload = {'email': email}
    r = requests.post('http://localhost:5000/reset_password', data=payload)
    assert r.status_code == 200

    reset_token = AUTH.get_reset_password_token(email)

    return r.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Test update password"""
    payload = {'email': email, 'reset_token': reset_token,
               'new_password': new_password}
    r = requests.put('http://localhost:5000/reset_password', data=payload)
    assert r.status_code == 200
    assert r.json() == {"email": email, "message": "Password updated"}


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
