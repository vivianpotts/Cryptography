'''Main application file for the Petition Crypto System'''

# Importing necessary functions from other modules
from user_management import register_user, authenticate_user, generate_csr
from pki_utils import sign_user_csr, verify_user_certificate
from petition_manager import create_petition, sign_petition, verify_signature

# Function to display the menu options to the user


def menu():
    '''Display menu and get user choice'''
    print("\n--- PETITION CRYPTO SYSTEM ---")
    print("1. Register user")  # Option to register a new user
    print("2. Login")  # Option to authenticate an existing user
    print("3. Generate CSR")  # Option to generate a Certificate Signing Request
    print("4. Issue Certificate (CA)")  # Option for the Certificate Authority to issue a certificate
    print("5. Create petition")  # Option to create a new petition
    print("6. Sign petition")  # Option to sign an existing petition
    print("7. Verify signature")  # Option to verify a petition signature
    print("0. Exit")  # Option to exit the application
    return input("> ")  # Prompt user for menu choice

# Main function to handle the application logic


def main():
    '''Main application loop'''
    while True:
        choice = menu()  # Display menu and get user choice

        if choice == "1":
            # Register a new user
            user = input("Username: ")  # Prompt for username
            pwd = input("Password: ")  # Prompt for password
            ok, msg = register_user(user, pwd)  # Call register_user function
            print(msg)  # Display the result message

        elif choice == "2":
            # Authenticate an existing user
            user = input("Username: ")  # Prompt for username
            pwd = input("Password: ")  # Prompt for password
            ok, msg = authenticate_user(user, pwd)  # Call authenticate_user function
            print(msg)  # Display the result message

        elif choice == "3":
            # Generate a Certificate Signing Request (CSR)
            user = input("Username: ")  # Prompt for username
            pwd = input("Password: ")  # Prompt for password
            csr = generate_csr(user, pwd)  # Call generate_csr function
            print("CSR generated:", csr)  # Display the generated CSR

        elif choice == "4":
            # Issue a certificate for a user
            user = input("Username: ")  # Prompt for username
            csr_path = f"data/{user}.csr.pem"  # Construct the path to the user's CSR file
            cert = sign_user_csr(user, csr_path)  # Call sign_user_csr function
            print("Cert issued:", cert)  # Display the issued certificate

        elif choice == "5":
            # Create a new petition
            title = input("Petition title: ")  # Prompt for petition title
            text = input("Petition text: ")  # Prompt for petition text
            ok, msg = create_petition(title, text)  # Call create_petition function
            print(msg)  # Display the result message

        elif choice == "6":
            # Sign an existing petition
            user = input("Username: ")  # Prompt for username
            pwd = input("Password: ")  # Prompt for password
            title = input("Petition title: ")  # Prompt for petition title
            ok, msg = sign_petition(user, pwd, title)  # Call sign_petition function
            print(msg)  # Display the result message

        elif choice == "7":
            # Verify a petition signature
            user = input("Username: ")  # Prompt for username
            title = input("Petition title: ")  # Prompt for petition title
            ok, msg = verify_signature(user, title)  # Call verify_signature function
            print(msg)  # Display the result message

        elif choice == "0":
            # Exit the application
            break

        else:
            # Handle invalid menu options
            print("Invalid option.")

# Entry point of the application


if __name__ == "__main__":
    main()
