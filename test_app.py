import requests, unittest
from bs4 import BeautifulSoup
import pytest
import app
import os
from bs4 import BeautifulSoup
WORDLIST = "wordlist.txt"

# @pytest.fixture
# def app():
#     testing_app = app.run()
#     testing_app.debug = True
#     return testing_app.test_client()


class TestSpellCheckApp(unittest.TestCase):
    def testHome(self):  # check Home endpoint for OK status
        assert (requests.get("http://localhost:5000/").status_code == 200)
    def testRegister(self):
        assert (requests.get("http://localhost:5000/register").status_code == 200)
    def testLogin(self):
        assert (requests.get("http://localhost:5000/login").status_code == 200)
    def testSpellCheck(self):
        assert (requests.get("http://localhost:5000/spell_check").status_code == 200)


if __name__=='__main__':
	unittest.main()