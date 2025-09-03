def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char) - shift_base + shift) % 26 + shift_base
            result += chr(shifted)
        else:
            result += char
    return result

def decrypt(text, shift):
    return encrypt(text, -shift)

def main():
    print("Caesar Cipher Encryption and Decryption")
    choice = input("Type 'e' to encrypt or 'd' to decrypt: ").lower()
    if choice not in ['e', 'd']:
        print("Invalid choice. Please select 'e' or 'd'.")
        return

    message = input("Enter your message: ")
    try:
        shift = int(input("Enter shift value (integer): "))
    except ValueError:
        print("Invalid shift value. Please enter an integer.")
        return

    if choice == 'e':
        encrypted = encrypt(message, shift)
        print(f"Encrypted message: {encrypted}")
    else:
        decrypted = decrypt(message, shift)
        print(f"Decrypted message: {decrypted}")

if __name__ == "__main__":
    main()
