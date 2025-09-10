from .base_account import BankAccount

class CheckingAccount(BankAccount):
    
    def applying_interest(self):
        self._record_transaction("Interest applied(checking)", 0)
        return self._balance

    def __str__(self):
        return f"Checking {super().__str__()}"