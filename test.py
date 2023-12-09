#ss2139, Suprim Sedhai

import unittest,sqlite3
import json,os
from jwks3 import app, DATABASE_FILE

class UnitTest(unittest.TestCase):


    def setUp(self):
        app.config['TESTING'] = True
        app.config['DEBUG'] = False
        self.app = app.test_client()
        #it uses the same database and not a new test database
        app.config['DATABASE'] = 'database.db'
        with app.app_context():
            conn = sqlite3.connect('database.db')
            cursor = conn.cursor()
            conn.commit()
            conn.close()


    def test_register_endpoint(self):
        # Test the registration endpoint
        data = {"username": "testuser", "email": "test@example.com"}
        response = self.app.post('/register', data=json.dumps(data), content_type='application/json')
        self.assertEqual(response.status_code, 201)

        # Check if the user is present in the database
        with app.app_context():
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute('SELECT id, password_hash FROM users WHERE username = ?', ('testuser',))
            user_id,password = cursor.fetchone()
            print(user_id,password)
            conn.close()

    def test_authentication_endpoint_user_not_found(self):
            # authenticate with a non-existent user
        auth_data = {"username": "nonexistentuser", "password": "password"}
        auth_response = self.app.post('/auth', data=json.dumps(auth_data), content_type='application/json')
        self.assertEqual(auth_response.status_code, 401)

    def test_authentication_endpoint_invalid_credentials(self):
            #  invalid credentials
        auth_data = {"username": "testuser", "password": "wrong_password"}
        auth_response = self.app.post('/auth', data=json.dumps(auth_data), content_type='application/json')

        self.assertEqual(auth_response.status_code, 401)



    def test_get_auth_logs_endpoint(self):
        # auth_logs endpoint
        response = self.app.get('/auth_logs')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
