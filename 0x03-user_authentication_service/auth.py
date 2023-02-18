#!/usr/bin/env python3
""" Auth class
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid


def _hash_password(password) -> str:
    """
    _hash_password.
    """
    byte = password.encode('utf-8')
    salt = bcrypt.gensalt()
    has = bcrypt.hashpw(byte, salt)
    return has


def _generate_uuid() -> str:
    """
    _generate_uuid.
    """
    a = uuid.uuid1()
    return str(a)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email, password) -> User:
        """
        register_user.
        """
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError('User' + email + 'already exists')
        except NoResultFound:
            hashpassword = _hash_password(password)
            use = self._db.add_user(email, hashpassword)
            return use

    def valid_login(self, email, password) -> bool:
        """
        valid_login.
        """
        try:
            user = self._db.find_user_by(email=email)
            password = password.encode('utf-8')
            if bcrypt.checkpw(password, user.hashed_password):
                return True
            else:
                return False
        except Exception:
            return False


    def create_session(self, email) -> str:
        """
        create_session.
        """
        try:
            user = self._db.find_user_by(email=email)
            idnum = _generate_uuid()
            self._db.update_user(user.id, session_id=idnum)
            return user.session_id
        except Exception:
            return None

    def get_user_from_session_id(self, session_id) -> str:
        """
        get_user_from_session_id.
        """
        if session_id:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except Exception:
            return None

    def destroy_session(self, user_id) -> None:
        """
                destroy_session.
                """
        user = self._db.find_user_by(id=user_id)
        setattr(user, "session_id", None)
        return None

    def get_reset_password_token(self, email) -> str:
        """
        get_reset_password_token.
        """
        try:
            user = self._db.find_user_by(email=email)
            sid = _generate_uuid()
            setattr(user, "reset_token", sid)
        except Exception:
            raise ValueError

    def update_password(self, reset_token, password) -> None:
        """
        update_password.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hash = _hash_password(password)
            setattr(user, "hashed_password", hash)
            setattr(user, "reset_token", None)
            return None
        except Exception:
            raise ValueError
