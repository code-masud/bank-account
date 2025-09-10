import unittest
import sys
import os
from models import SavingAccount, CheckingAccount

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestBankAccounts(unittest.TestCase):
    
    def test_savings_account_creation(self):
        account = SavingAccount("TEST001", "Test User", 1000, "testpass", 0.02)
        self.assertEqual(account.get_balance("testpass"), 1000)
    
    def test_checking_account_creation(self):
        account = CheckingAccount("TEST002", "Test User", 500, "testpass")
        self.assertEqual(account.get_balance("testpass"), 500)
    
    def test_deposit_and_withdraw(self):
        account = SavingAccount("TEST003", "Test User", 1000, "testpass")
        account.deposit(500, "testpass")
        self.assertEqual(account.get_balance("testpass"), 1500)
        
        account.withdraw(200, "testpass")
        self.assertEqual(account.get_balance("testpass"), 1300)
    
    def test_interest_application(self):
        account = SavingAccount("TEST004", "Test User", 1000, "testpass", 0.1)
        account.applying_interest()
        self.assertAlmostEqual(account.get_balance("testpass"), 1100)
    
    def test_password_authentication(self):
        account = SavingAccount("TEST005", "Test User", 1000, "correctpass")
        self.assertTrue(account.authenticate("correctpass"))
        self.assertFalse(account.authenticate("wrongpass"))

if __name__ == "__main__":
    unittest.main()