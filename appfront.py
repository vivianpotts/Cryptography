# petition_app_step1.py
# This script implements a simple in-memory user registration and login system.

# In-memory "database" to store user credentials
users = {}

def register_user():
    """
    Handles user registration by prompting for a username and password.
    Checks if the username already exists in the in-memory database.
    If not, registers the user with the provided password.
    """
    print("\n--- User Registration ---")
    username = input("Enter username: ").strip()  # Prompt for username
    if username in users:  # Check if username already exists
        print("❌ Username already exists.")
        return

    password = input("Enter password: ").strip()  # Prompt for password
    users[username] = password  # Store the username and password in the database
    print(f"✅ User '{username}' registered successfully!")

def login_user():
    """
    Handles user login by prompting for a username and password.
    Verifies the credentials against the in-memory database.
    If valid, welcomes the user; otherwise, displays an error message.
    """
    print("\n--- User Login ---")
    username = input("Enter username: ").strip()  # Prompt for username
    password = input("Enter password: ").strip()  # Prompt for password

    # Check if the username exists and the password matches
    if username in users and users[username] == password:
        print(f"✅ Welcome back, {username}!")
    else:
        print("❌ Invalid username or password.")

def main_menu():
    """
    Displays the main menu for the application.
    Allows the user to choose between registering, logging in, or exiting the application.
    """
    while True:
        print("\n=== Petition App ===")
        print("1. Register")  # Option to register a new user
        print("2. Login")  # Option to log in as an existing user
        print("3. Exit")  # Option to exit the application
        choice = input("Choose an option: ").strip()  # Prompt for user choice

        # Handle user choice
        if choice == "1":
            register_user()  # Call the registration function
        elif choice == "2":
            login_user()  # Call the login function
        elif choice == "3":
            print("👋 Goodbye!")  # Exit the application
            break
        else:
            print("Invalid option. Try again.")  # Handle invalid input

# Entry point of the script
if __name__ == "__main__":
    main_menu()  # Start the application
