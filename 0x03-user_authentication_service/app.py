#!/usr/bin/env python3
"""
Flask class
"""

from flask import Flask, jsonify, abort, request, redirect
from auth import Auth

app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def app():
    """
    GET Return: - welcome
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """
    POST /users Return: - message
    """
    email = request.form.get('email')
    password = request.form.get('password')
    AUTH = Auth()
    try:
        AUTH.register_user(email, password)
        return jsonify(email=email, message="user created")
    except ValueError:
        response = jsonify({"message": "email already registered"})
        return response


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """
    POST /sessions Return: - message
    """
    email = request.form.get('email')
    password = request.form.get('password')
    AUTH = Auth()
    auth = AUTH.valid_login(email, password)
    if auth:
        session_id = AUTH.create_session(email)
        response = jsonify({"email": f"{email}", "message": "logged in"})
        response.set_cookie('session_id', session_id)
        return response
    else:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """
    DELETE /sessions Return: - message
    """
    session_id = request.cookies.get('session_id')
    user = Auth().get_user_from_session_id(session_id)
    if user:
        Auth().destroy_session(user.id)
        return redirect('/')
    else:
        abort(403)


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile():
    """
    GET /profile Return: - message
    """
    session_id = request.cookies.get('session_id')
    user = Auth().get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": f"{user.email}"}), 200

    else:
        abort(403)


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token():
    """
    POST /reset_password Return: - message
    """
    email = request.form.get('email')
    try:
        token = Auth().get_reset_password_token(email)
        return jsonify({"email": f"{email}", "reset_token": f"{token}"}), 200
    except Exception:
        abort(403)


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password():
    """
    PUT /reset_password Return: - message
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        Auth().update_password(reset_token, new_password)
        return jsonify({"email": f"{email}", "message": f"{new_password}"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
