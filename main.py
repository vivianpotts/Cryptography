from user_management import register_user, authenticate_user, generate_csr
from pki_utils import sign_user_csr, verify_user_certificate
from petition_manager import create_petition, sign_petition, verify_signature

def menu():
    print("\n--- PETITION CRYPTO SYSTEM ---")
    print("1. Register user")
    print("2. Login")
    print("3. Generate CSR")
    print("4. Issue Certificate (CA)")
    print("5. Create petition")
    print("6. Sign petition")
    print("7. Verify signature")
    print("0. Exit")
    return input("> ")


def main():
    while True:
        choice = menu()

        if choice == "1":
            user = input("Username: ")
            pwd = input("Password: ")
            ok, msg = register_user(user, pwd)
            print(msg)

        elif choice == "2":
            user = input("Username: ")
            pwd = input("Password: ")
            ok, msg = authenticate_user(user, pwd)
            print(msg)

        elif choice == "3":
            user = input("Username: ")
            pwd = input("Password: ")
            csr = generate_csr(user, pwd)
            print("CSR generated:", csr)

        elif choice == "4":
            user = input("Username: ")
            csr_path = f"data/{user}.csr.pem"
            cert = sign_user_csr(user, csr_path)
            print("Cert issued:", cert)

        elif choice == "5":
            title = input("Petition title: ")
            text = input("Petition text: ")
            ok, msg = create_petition(title, text)
            print(msg)

        elif choice == "6":
            user = input("Username: ")
            pwd = input("Password: ")
            title = input("Petition title: ")
            ok, msg = sign_petition(user, pwd, title)
            print(msg)

        elif choice == "7":
            user = input("Username: ")
            title = input("Petition title: ")
            ok, msg = verify_signature(user, title)
            print(msg)

        elif choice == "0":
            break

        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
