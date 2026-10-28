from app.auth import hash_password, verify_password
from app import create_app


def test_hash_verify():
    h, s = hash_password('testpass')
    assert verify_password('testpass', h, s)
    assert not verify_password('wrong', h, s)


def test_app_factory():
    app = create_app()
    assert app is not None
