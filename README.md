# S3KC Auth Demo

This is a simple Flask app that demonstrates various authentication methods including password-based auth and TOTP.

The source code contains 4 TODO tasks that you need to complete to implement the various authentication methods.

## Start up

1. Install the dependencies
```
pip install -r requirements.txt
```

2. Run the server
```
python server.py
```

## Tasks

1. Implement secure password hashing using [bcrypt](https://pypi.org/project/bcrypt/)
2. Implement secure password verification
3. Implement password change functionality
4. Implement TOTP secret generation

## Extra Credit

If this was too easy, try adding a WebAuthn registration and authentication flow, using the [webauthn](https://pypi.org/project/webauthn/) package.

```pip install webauthn```
