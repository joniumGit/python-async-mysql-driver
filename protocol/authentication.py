from hashlib import sha1


def native_password(password: str, auth_data: bytes):
    auth_data = auth_data[:20]  # Discard one extra byte
    password = password.encode('utf-8')
    password = bytes(
        a ^ b
        for a, b in
        zip(
            sha1(password).digest(),
            sha1(auth_data + sha1(sha1(password).digest()).digest()).digest()
        )
    )
    return password
