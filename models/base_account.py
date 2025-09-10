from datetime import datetime
from utils.security import hash_password, verify_password

class BankAccount:
    def __init__(self, account_number, owner_name, initial_balance=0, password=""):
        self._account_number = account_number
        self._owner_name = owner_name
        self._balance = initial_balance
        self._password_hash = self._set_password(password)
        self._transactions = []
        self._record_transaction("Account created", initial_balance)

    def _set_password(self, password):
        if password is None:
            return None
        return hash_password(password)

    def authenticate(self, password):
        if self._password_hash is None:
            return False
            
        return verify_password(password, self._password_hash)

    def _record_transaction(self, description, amount):
        timestamp = datetime.now().strftime("%Y-%M-%D %H:%M:%S")
        self._transactions.append({
            'timestamp': timestamp,
            'description': description,
            'amount': amount,
            'balance_after': self._balance
        })

    def deposit(self, amount, password):
        if not self.authenticate:
            raise ValueError("Incorrect password")

        if amount <= 0:
            print("Deposit amount must be positive")

        self._balance += amount
        self._record_transaction('Deposit', amount)
        return self._balance

    def withdraw(self, amount, password):
        if not self.authenticate(password):
            raise ValueError("Incorrect password")

        if amount <= 0:
            print("Withdraw amount must be positive")
        elif amount > self._balance:
            print("Insufficient fund")

        self._balance -= amount
        self._record_transaction("Withdraw", -amount)
        return self._balance

    def get_balance(self, password):
        if not self.authenticate(password):
            raise ValueError("Incorrect password")

        return self._balance

    def get_transactions(self, password):
        if not self.authenticate(password):
            raise ValueError("Incorrect password")
        
        return self._transactions.copy()

    def applying_interest(self):
        pass

    def __str__(self):
        return f"Account: {self._account_number}, Owner: {self._owner_name}, Balance: {self._balance:,.2f}"
