class Encode:
    def __init__(self, plaintext, key):
        self.plaintext = plaintext
        self.key = key.upper()

    def encrypt(self):
        ciphertext = ""
        idx = 0
        for char in self.plaintext.lower():
            if char.isalpha():
                key_idx = self.key[idx % len(self.key)]
                # print(f"Key Index: {key_idx}")
                shift = ((ord(char) - ord("a")) + (ord(key_idx) - ord("A"))) % 26
                # print(f"Shift: {shift}, Char: {char}, Key: {key_idx}")
                ciphertext += chr(shift + ord("a")).upper()
                idx += 1
            else:
                ciphertext += char.upper()
        return ciphertext


class Decode:
    def __init__(self, ciphertext, key):
        self.ciphertext = ciphertext
        self.key = key.upper()

    def decrypt(self):
        if not self.key:
            return "Key is required for decryption. Please provide a valid key."
        plaintext = ""
        idx = 0
        for char in self.ciphertext.upper():
            if char.isalpha():
                key_idx = self.key[idx % len(self.key)]
                shift = ((ord(char) - ord("A")) - (ord(key_idx) - ord("A"))) % 26
                # print(f"Shift: {shift}, Char: {char}, Key: {key_idx}")
                plaintext += chr(shift + ord("A")).lower()
                idx += 1
            else:
                plaintext += char.lower()
        return plaintext



if __name__ == "__main__":
    while True:
        print(
            """<------- Vignere Cipher Program ------->\n
        Choose Your Option
        1. Encode
        2. Decode
        3. Exit\n"""
        )
        option = input("Enter your option (1 or 2 or 3): ")
        if option == "1":
            print("\n<" + "-" * 20 + "Encoding" + "-" * 20 + ">\n")
            plaintext = input("Enter the Plaintext: ")
            key = input("Enter the Key: ")
            cipher = Encode(plaintext, key)
            print(f"Ciphertext: {cipher.encrypt()}\n")
        elif option == "2":
            print("\n<" + "-" * 20 + "Decoding" + "-" * 20 + ">\n")
            ciphertext = input("Enter the Ciphertext: ")
            key = input("Please Enter the Key : ")
            cipher = Decode(ciphertext, key)
            print(f"Plaintext: {cipher.decrypt()}\n")
        elif option == "3":
            print("Exiting the program.")
            break
        else:
            print("Invalid option. Please try again.")
