import unittest
from security import hash_password, verify_password

class TestSecurity(unittest.TestCase):
    
    def test_password_hashing(self):
        """Test that password hashing and verification works correctly"""
        password = "securepassword123"
        hashed = hash_password(password)
        
        # Should verify correctly with right password
        self.assertTrue(verify_password(password, hashed))
        
        # Should fail with wrong password
        self.assertFalse(verify_password("wrongpassword", hashed))
        
        # Should fail with None password when hash exists
        self.assertFalse(verify_password(None, hashed))
    
    def test_none_password(self):
        """Test handling of None passwords"""
        # Hash a None password should return None
        hashed = hash_password(None)
        self.assertIsNone(hashed)
        
        # Verify None against None should return True
        self.assertTrue(verify_password(None, None))
        
        # Verify None against actual hash should return False
        actual_hash = hash_password("realpassword")
        self.assertFalse(verify_password(None, actual_hash))
        
        # Verify actual password against None hash should return False
        self.assertFalse(verify_password("realpassword", None))
    
    def test_salt_uniqueness(self):
        """Test that same password produces different hashes due to salt"""
        password = "mypassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # Hashes should be different due to different salts
        self.assertNotEqual(hash1, hash2)
        
        # Both should verify correctly
        self.assertTrue(verify_password(password, hash1))
        self.assertTrue(verify_password(password, hash2))
        
        # Hashes should have correct structure (salt + hash)
        self.assertEqual(len(hash1), 96)  # 32 chars salt + 64 chars hash
        self.assertEqual(len(hash2), 96)
    
    def test_empty_password(self):
        """Test handling of empty string password"""
        empty_hash = hash_password("")
        self.assertIsNotNone(empty_hash)
        self.assertTrue(verify_password("", empty_hash))
        self.assertFalse(verify_password(" ", empty_hash))  # Space is different

if __name__ == "__main__":
    unittest.main()