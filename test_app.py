import requests, unittest


class TestSpellCheckApp(unittest.TestCase):
    def testHome(self):  # check Home endpoint for OK status
        assert (requests.get("http://localhost:5000/").status_code == 200)
    def testRegister(self):
        assert (requests.get("http://localhost:5000/register").status_code == 200)
    def testLogin(self):
        assert (requests.get("http://localhost:5000/login").status_code == 200)
    def testSpellCheck(self):
        assert (requests.get("http://localhost:5000/spell_check").status_code == 200)


if __name__ == '__main__':
    unittest.main()