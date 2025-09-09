from base_account import BankAccount

class SavingAccount(BankAccount):
    def __init__(self, account_number, owner_name, initial_balance=0, password="", interest_rate=0.02):
        super().__init__(account_number, owner_name, initial_balance, password)
        self._interest_rate = interest_rate

    def applying_interest(self):
        interest_amount = self._balance * self._interest_rate
        self._balance += interest_amount
        self._record_transaction('Interest applied(Saving)', interest_amount)
        return self._balance

    @property
    def interest_rate(self):
        return self._interest_rate

    @interest_rate.setter
    def interest_rate(self, new_rate):
        if new_rate < 0:
            raise ValueError("Interest rate must be positive")

        self._interest_rate = new_rate

    def __str__(self):
        return f"Saving {super().__str__()}, Rate: {(self._interest_rate * 100):,.2f}%"
