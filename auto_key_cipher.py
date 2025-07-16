class Encode:
    def __init__(self, plaintext, key):
        self.plaintext = plaintext
        self.key = key

    def encrypt(self):
        ciphertext = ""
        for char in self.plaintext.lower():
            if char.isalpha():
                shift = ((ord(char) - ord("a")) + self.key) % 26
                ciphertext += chr(shift + ord("a")).upper()
                self.key = ord(char) - ord("a")
            else:
                ciphertext += char.upper()
        return ciphertext


class Decode:
    def __init__(self, ciphertext, key=None):
        self.ciphertext = ciphertext
        self.key = key

    def decrypt(self):
        if self.key is None:
            return "Key is required for decryption. Please provide a valid key."
        plaintext = ""
        for char in self.ciphertext.upper():
            if char.isalpha():
                shift = (ord(char) - ord("A") - self.key) % 26
                # print(shift, ord(char), self.key)
                plaintext += chr(shift + ord("A")).lower()
                self.key = shift
            else:
                plaintext += char.lower()
        return plaintext

    def brute_force_decrypt(self):
        for key in range(26):
            self.key = key
            print(f"Key : {key:2d} , Plaintext: {self.decrypt()}")


if __name__ == "__main__":
    while True:
        print(
            """<------- Auto Key Cipher Program ------->\n
        Choose Your Option
        1. Encode
        2. Decode
        3. Exit\n"""
        )
        option = input("Enter your option (1 or 2 or 3): ")
        if option == "1":
            print("\n<" + "-" * 20 + "Encoding" + "-" * 20 + ">\n")
            plaintext = input("Enter the Plaintext: ")
            try:
                key = int(input("Enter the Key: "))
            except ValueError:
                print("Invalid key. Please enter a valid integer.")
                continue
            cipher = Encode(plaintext, key)
            print(f"Ciphertext: {cipher.encrypt()}\n")
        elif option == "2":
            print("\n<" + "-" * 20 + "Decoding" + "-" * 20 + ">\n")
            ciphertext = input("Enter the Ciphertext: ")
            key = input("Do you Have the key? if not press Enter: ")
            if key:
                try:
                    key = int(key)
                except ValueError:
                    print("Invalid key. Please enter a valid integer.")
                    continue
                cipher = Decode(ciphertext, key)
                print(f"Plaintext: {cipher.decrypt()}\n")
            else:
                cipher = Decode(ciphertext)
                cipher.brute_force_decrypt()
        elif option == "3":
            print("Exiting the program.")
            break
        else:
            print("Invalid option. Please try again.")
