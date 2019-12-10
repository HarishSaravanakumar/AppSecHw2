import tempfile
import os
import pytest
from werkzeug.security import generate_password_hash

with open(os.path.join(os.path.dirname(__file__), 'test.sql'), 'rb') as f:
    _data_sql = f.read().decode('utf8')


@pytest.fixture
def app():
    db_fd, db_path = tempfile.mkstemp()

    app = create_app({
        'TESTING': True,
        'DATABASE': db_path,
    })

    with app.app_context():
        init_db()
        get_db().executescript(_data_sql)
        dbobj = get_db()
        dbobj.execute('INSERT INTO userCreds (uname, pword,twofa, level) VALUES (?, ?, ?, ?)',
                      ('admin', generate_password_hash('Administrator@1'), '12345678901', True))
        dbobj.commit()

    yield app

    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth(client):
    return LoginAuth(client)


class LoginAuth(object):
    def __init__(self, client):
        self._client = client

    def login(self, uname='harish', pword='yoo123', twofa='12345678901'):
        return self._client.post(
            '/login',
            data={'uname': uname, 'pword': pword, '2fa': twofa}
        )

    def admin_login(self, uname='admin', pword='Administrator@1', twofa='12345678901'):
        return self._client.post(
            '/login',
            data={'uname': uname, 'pword': pword, '2fa': twofa}
        )

    def logout(self):
        return self._client.get('/logout')


