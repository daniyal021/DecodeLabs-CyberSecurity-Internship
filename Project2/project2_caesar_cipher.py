"""
Cyber Security - Project 2
Basic Encryption & Decryption (Caesar Cipher)
DecodeLabs Industrial Training Kit
"""


def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                result += chr((ord(char) - 97 + shift) % 26 + 97)
        else:
            result += char
    return result


def decrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr((ord(char) - 65 - shift) % 26 + 65)
            else:
                result += chr((ord(char) - 97 - shift) % 26 + 97)
        else:
            result += char
    return result


def main():
    print("=" * 40)
    print("   CAESAR CIPHER - ENCRYPT / DECRYPT")
    print("=" * 40)

    while True:
        print("\n1. Encrypt")
        print("2. Decrypt")
        print("3. Encrypt + Decrypt (round trip test)")
        print("4. Exit")
        choice = input("Choose an option (1-4): ").strip()

        if choice == "1":
            message = input("Enter Message: ")
            shift = int(input("Enter Shift Key: "))
            print("\nOriginal :", message)
            print("Encrypted:", encrypt(message, shift))

        elif choice == "2":
            message = input("Enter Message: ")
            shift = int(input("Enter Shift Key: "))
            print("\nOriginal :", message)
            print("Decrypted:", decrypt(message, shift))

        elif choice == "3":
            message = input("Enter Message: ")
            shift = int(input("Enter Shift Key: "))
            encrypted = encrypt(message, shift)
            decrypted = decrypt(encrypted, shift)
            print("\nOriginal :", message)
            print("Encrypted:", encrypted)
            print("Decrypted:", decrypted)

        elif choice == "4":
            print("Goodbye!")
            break

        else:
            print("Invalid option, please choose 1-4.")


if __name__ == "__main__":
    main()
