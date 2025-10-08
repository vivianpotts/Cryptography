
# petition_app_step1.py

# In-memory "database"
users = {}

def register_user():
    print("\n--- User Registration ---")
    username = input("Enter username: ").strip()
    if username in users:
        print("❌ Username already exists.")
        return

    password = input("Enter password: ").strip()
    users[username] = password
    print(f"✅ User '{username}' registered successfully!")

def login_user():
    print("\n--- User Login ---")
    username = input("Enter username: ").strip()
    password = input("Enter password: ").strip()

    if username in users and users[username] == password:
        print(f"✅ Welcome back, {username}!")
    else:
        print("❌ Invalid username or password.")

def main_menu():
    while True:
        print("\n=== Petition App ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice == "3":
            print("👋 Goodbye!")
            break
        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    main_menu()
