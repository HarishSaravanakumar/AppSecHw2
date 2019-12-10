import requests, unittest
import pytest
from db import get_db


class TestSpellCheckApp(unittest.TestCase):
    def testHome(self):  # check Home endpoint for OK status
        assert (requests.get("http://localhost:5000/").status_code == 200)
    def testRegister(self):
        assert (requests.get("http://localhost:5000/register").status_code == 200)
    def testLogin(self):
        assert (requests.get("http://localhost:5000/login").status_code == 200)
    def testSpellCheck(self):
        assert (requests.get("http://localhost:5000/spell_check").status_code == 200)
    def testHistory(self):
        assert (requests.get("http://localhost:5000/history").status_code == 200)
    def testLoginHistory(self):
        assert (requests.get("http://localhost:5000/login_history").status_code == 200)


def test_register(client, app):
    assert client.get('/register').status_code == 200
    response = client.post(
        '/register', data={'uname': 'abcde', 'pword': 'abc123', '2fa': '1234567890'}
    )
    with app.app_context():
        assert get_db().execute(
            "select * from user where username = 'a'",
        ).fetchone() is not None
def test_login(client, auth):
    response = auth.login()
    with client:
        assert client.get('/login').status_code==302
        assert client.get('/spell_check').status_code==200
        assert session['user_id'] == 2
        assert g.userCreds['uname'] == 'abcde'
        assert g.userCreds['pword'] == 'abc123'
        assert g.userCreds['twofa'] == '1234567890'

if __name__ == '__main__':
    unittest.main()

