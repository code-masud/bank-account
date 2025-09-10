import unittest
from utils.security import hash_password, verify_password

class TestSecurity(unittest.TestCase):
    
    def test_password_hashing(self):
        password = "securepassword123"
        hashed = hash_password(password)
        
        self.assertTrue(verify_password(password, hashed))
        
        self.assertFalse(verify_password("wrongpassword", hashed))
    
        self.assertFalse(verify_password(None, hashed))
    
    def test_none_password(self):

        hashed = hash_password(None)
        self.assertIsNone(hashed)
        
        self.assertTrue(verify_password(None, None))
        
        actual_hash = hash_password("realpassword")
        self.assertFalse(verify_password(None, actual_hash))
        
        self.assertFalse(verify_password("realpassword", None))
    
    def test_salt_uniqueness(self):
        password = "mypassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        self.assertNotEqual(hash1, hash2)
        
        self.assertTrue(verify_password(password, hash1))
        self.assertTrue(verify_password(password, hash2))
        
        self.assertEqual(len(hash1), 96)
        self.assertEqual(len(hash2), 96)
    
    def test_empty_password(self):
        empty_hash = hash_password("")
        self.assertIsNotNone(empty_hash)
        self.assertTrue(verify_password("", empty_hash))
        self.assertFalse(verify_password(" ", empty_hash)) 

if __name__ == "__main__":
    unittest.main()