#!/usr/bin/env python3
"""This module implements password hashing with bcrypt"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Implement a hash password"""
    bytes = password.encode()
    hash = bcrypt.hashpw(bytes, bcrypt.gensalt())
    return hash


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Check valid password"""
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hashed_password):
        valid = True
    return valid
