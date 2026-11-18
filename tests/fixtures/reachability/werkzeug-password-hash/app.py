from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password):
    return generate_password_hash(password)


def verify(stored, password):
    return check_password_hash(stored, password)
