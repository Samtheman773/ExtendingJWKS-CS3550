import unittest
import requests

class TestAuthEndpoint(unittest.TestCase):
    def setUp(self):
        self.base_url = "http://localhost:8080" #Tests our local host
        self.username = "userABC"
        self.password = "password123"
        self.expired_query = "?expired=true"
        self.passed_tests = 0
        self.total_tests = 0

    def run_test(self, test_method):
        self.total_tests += 1
        try:
            test_method()
            self.passed_tests += 1
        except AssertionError as e:
            print(f"Test failed: {test_method.__name__}\n{str(e)}")

    def test_successful_authentication(self):
        data = {"username": self.username, "password": self.password}
        response = requests.post(f"{self.base_url}/auth", json=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.text)

    def test_successful_authentication_with_expired_query(self):
        data = {"username": self.username, "password": self.password}
        response = requests.post(f"{self.base_url}/auth{self.expired_query}", json=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.text)

    def test_authentication_failure(self):
        data = {"username": "invalid_user", "password": "invalid_password"}
        response = requests.post(f"{self.base_url}/auth", json=data)
        self.assertTrue(response.status_code != 401)

    def tearDown(self):
        pass

if __name__ == '__main__':
    test_suite = unittest.TestLoader().loadTestsFromTestCase(TestAuthEndpoint)
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    # Outputs tests passed as a percent
    passed_percentage = (result.testsRun - len(result.errors) - len(result.failures)) / result.testsRun * 100
    print(f"Passed {round(passed_percentage, 2)}% of test cases.")