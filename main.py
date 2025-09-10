from models import SavingAccount, CheckingAccount

def demonstrated_accounts():
    print("=== Bank Account Management System ===")

    print("Creating accounts...")
    alice_savings = SavingAccount("SA001", "Alice", 1000, "alice123", 0.03)
    bob_checking = CheckingAccount("CA001", "Bob", 500, "bob456")
    
    print(f"Created: {alice_savings}")
    print(f"Created: {bob_checking}\n")

    print("=== Transactions ===")
    alice_savings.deposit(200, "alice123")
    print(f"Alice deposited $200: ${alice_savings.get_balance('alice123')}")
    
    bob_checking.withdraw(100, "bob456")
    print(f"Bob withdrew $100: ${bob_checking.get_balance('bob456')}\n")

    print("=== Applying Interest ===")
    alice_savings.applying_interest()
    print(f"After interest: {alice_savings}")

    bob_checking.applying_interest()
    print(f"After interest: {bob_checking}\n")

    print("=== Alice's Transaction History ===")
    for transaction in alice_savings.get_transactions('alice123'):
        print(f"{transaction['timestamp']}: {transaction['description']} "
              f"${transaction['amount']:.2f} (Balance: ${transaction['balance_after']:.2f})")
    
    # Demonstrate password protection
    print("\n=== Password Protection ===")
    try:
        alice_savings.get_balance("wrongpassword")
    except ValueError as e:
        print(f"Security test passed: {e}")

def main():
    try:
        demonstrated_accounts()
    except Exception as e:
        print(f"An error occurred: {e}")
        return 1
    return 0

if __name__ == "__main__":
    exit(main())