class Encode:
    def __init__(self, plaintext, key1, key2):
        self.plaintext = plaintext
        self.key1 = key1
        self.key2 = key2

    def gcd(self):
        if self.key1 is None or self.key2 is None:
            raise ValueError(
                "Key is required for decryption. Please provide a valid key."
            )
        r1, r2 = 26, self.key1
        while r2 != 0:
            r1, r2 = r2, r1 % r2
        return r1

    def encrypt(self):
        if self.gcd() != 1:
            return "Key value is not coprime with 26, decryption not possible."
        ciphertext = ""
        for char in self.plaintext.lower():
            if char.isalpha():
                shift = (((ord(char) - ord("a")) * self.key1) + self.key2) % 26
                ciphertext += chr(shift + ord("a")).upper()
            else:
                ciphertext += char.upper()
        return ciphertext


class Decode:
    def __init__(self, ciphertext, key1=None, key2=None):
        self.ciphertext = ciphertext
        self.key1 = key1
        self.key2 = key2

    def gcd(self):
        if self.key1 is None:
            raise ValueError(
                "Key is required for decryption. Please provide a valid key."
            )
        r1, r2 = 26, self.key1
        while r2 != 0:
            r1, r2 = r2, r1 % r2
        return r1

    def multiplicative_inverse(self):
        if self.key1 is None:
            raise ValueError(
                "Key is required for decryption. Please provide a valid key."
            )
        r1, r2 = 26, self.key1
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
        if self.key1 is None or self.key2 is None:
            return "Key is required for decryption. Please provide a valid key."
        if self.gcd() != 1:
            return "Key value is not coprime with 26, decryption not possible."
        plaintext = ""
        for char in self.ciphertext.upper():
            if char.isalpha():
                inv_key = self.multiplicative_inverse()
                shift = (((ord(char) - ord("A")) - self.key2) * inv_key) % 26
                plaintext += chr(shift + ord("A")).lower()
            else:
                plaintext += char.lower()
        return plaintext

    def brute_force_decrypt(self):
        def gcd_helper(a, b):
            while b != 0:
                a, b = b, a % b
            return a

        valid_keys1 = [key for key in range(1, 26) if gcd_helper(26, key) == 1]

        if self.key1 is None and self.key2 is None:
            print("Trying all possible key combinations...")
            for key1 in valid_keys1:
                for key2 in range(26):
                    self.key1, self.key2 = key1, key2
                    result = self.decrypt()
                    print(f"Key1: {key1:2d}, Key2: {key2:2d} -> {result}")

        elif self.key1 is not None and self.key2 is None:
            if self.gcd() != 1:
                print(f"Error: Key1 ({self.key1}) is not coprime with 26")
                return
            print(f"Trying all Key2 values with Key1={self.key1}...")
            for key2 in range(26):
                self.key2 = key2
                result = self.decrypt()
                print(f"Key1: {self.key1:2d}, Key2: {key2:2d} -> {result}")

        elif self.key1 is None and self.key2 is not None:
            print(f"Trying all Key1 values with Key2={self.key2}...")
            for key1 in valid_keys1:
                self.key1 = key1
                result = self.decrypt()
                print(f"Key1: {key1:2d}, Key2: {self.key2:2d} -> {result}")

        else:
            result = self.decrypt()
            print(f"Key1: {self.key1}, Key2: {self.key2} -> {result}")


if __name__ == "__main__":
    while True:
        print(
            """<------- Affine Cipher Program ------->\n
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
                key1 = int(input("Enter the Key1: "))
                key2 = int(input("Enter the Key2: "))
            except ValueError:
                print("Invalid key. Please enter a valid integer.")
                continue
            cipher = Encode(plaintext, key1, key2)
            print(f"Ciphertext: {cipher.encrypt()}\n")
        elif option == "2":
            print("\n<" + "-" * 20 + "Decoding" + "-" * 20 + ">\n")
            ciphertext = input("Enter the Ciphertext: ")
            key1 = input("Do you Have the key1? if not press Enter: ")
            key2 = input("Do you Have the key2? if not press Enter: ")
            if key1 or key2:
                try:
                    key1 = int(key1) if key1 else None
                    key2 = int(key2) if key2 else None
                except ValueError:
                    print("Invalid key. Please enter a valid integer.")
                    continue
                cipher = Decode(ciphertext, key1, key2)
                if key1 is not None and key2 is not None:
                    print(f"Plaintext: {cipher.decrypt()}\n")
                else:
                    cipher.brute_force_decrypt()
            else:
                cipher = Decode(ciphertext)
                cipher.brute_force_decrypt()
        elif option == "3":
            print("Exiting the program.")
            break
        else:
            print("Invalid option. Please try again.")
