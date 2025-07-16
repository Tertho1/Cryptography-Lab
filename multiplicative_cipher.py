class Encode:
    def __init__(self, plaintext, key):
        self.plaintext = plaintext
        self.key = key

    def gcd(self):
        if self.key is None:
            raise ValueError(
                "Key is required for decryption. Please provide a valid key."
            )
        r1, r2 = 26, self.key
        while r2 != 0:
            r1, r2 = r2, r1 % r2
        return r1

    def encrypt(self):
        if self.gcd() != 1:
            return "Key value is not coprime with 26, decryption not possible."
        ciphertext = ""
        for char in self.plaintext.lower():
            if char.isalpha():
                shift = ((ord(char) - ord("a")) * self.key) % 26
                ciphertext += chr(shift + ord("a")).upper()
            else:
                ciphertext += char.upper()
        return ciphertext


class Decode:
    def __init__(self, ciphertext, key=None):
        self.ciphertext = ciphertext
        self.key = key

    def gcd(self):
        if self.key is None:
            raise ValueError(
                "Key is required for decryption. Please provide a valid key."
            )
        r1, r2 = 26, self.key
        while r2 != 0:
            r1, r2 = r2, r1 % r2
        return r1

    def multiplicative_inverse(self):
        if self.key is None:
            raise ValueError(
                "Key is required for decryption. Please provide a valid key."
            )
        r1, r2 = 26, self.key
        t1, t2 = 0, 1
        while r2 != 0:
            q = r1 // r2
            r = r1 % r2
            r1, r2 = r2, r

            t = t1 - q * t2
            t1, t2 = t2, t
        if r1 != 1:
            raise ValueError(
                "Key value is not coprime with 26, decryption not possible."
            )
        return t1 % 26

    def decrypt(self):
        if self.key is None:
            return "Key is required for decryption. Please provide a valid key."
        if self.gcd() != 1:
            return "Key value is not coprime with 26, decryption not possible."
        plaintext = ""
        for char in self.ciphertext.upper():
            if char.isalpha():
                inv_key = self.multiplicative_inverse()
                shift = ((ord(char) - ord("A")) * inv_key) % 26
                plaintext += chr(shift + ord("A")).lower()
            else:
                plaintext += char.lower()
        return plaintext

    def brute_force_decrypt(self):
        for key in range(1, 27):
            self.key = key
            if self.gcd() != 1:
                continue
            print(f"Key : {key:2d} , Plaintext: {self.decrypt()}")


if __name__ == "__main__":
    while True:
        print(
            """<------- Multiplicative Cipher Program ------->\n
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
