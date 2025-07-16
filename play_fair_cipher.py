class Encode:
    def __init__(self, plaintext, key):
        self.plaintext = plaintext
        self.key = key

    def modify_plaintext(self):
        self.plaintext = self.plaintext.upper().replace("J", "I").replace(" ", "")
        # print(self.key)
        modified_plaintext = []
        temp = ""
        i = 0
        while i < len(self.plaintext):
            temp += self.plaintext[i]
            if i + 1 < len(self.plaintext):
                if self.plaintext[i] == self.plaintext[i + 1]:
                    temp += "X"
                    modified_plaintext.append(temp)
                    i += 1
                else:
                    temp += self.plaintext[i + 1]
                    modified_plaintext.append(temp)
                    i += 2
            else:
                temp += "X"
                modified_plaintext.append(temp)
                i += 1
            temp = ""
        # print("Modified Plaintext:", modified_plaintext)
        return modified_plaintext

    def find_index(self, key, char):
        char = char.upper().replace("J", "I")
        for i in range(5):
            for j in range(5):
                if key[i][j] == char:
                    return i, j
        return -1, -1

    def encrypt(self):
        ciphertext = ""
        modified_plaintext = self.modify_plaintext()
        # print("Modified Plaintext:", modified_plaintext)
        for text in modified_plaintext:
            r1, c1 = self.find_index(self.key, text[0])
            r2, c2 = self.find_index(self.key, text[1])
            if r1 == r2:
                ciphertext += self.key[r1][(c1 + 1) % 5] + self.key[r2][(c2 + 1) % 5]
            elif c1 == c2:
                ciphertext += self.key[(r1 + 1) % 5][c1] + self.key[(r2 + 1) % 5][c2]
            else:
                ciphertext += self.key[r1][c2] + self.key[r2][c1]

        return ciphertext


class Decode:
    def __init__(self, ciphertext, key):
        self.ciphertext = ciphertext
        self.key = key

    def find_index(self, key, char):
        char = char.upper().replace("J", "I")
        for i in range(5):
            for j in range(5):
                if key[i][j] == char:
                    return i, j
        return -1, -1

    def decrypt_pair(self, pair):
        if self.key is None:
            return "Key is required for decryption. Please provide a valid key."

        r1, c1 = self.find_index(self.key, pair[0])
        r2, c2 = self.find_index(self.key, pair[1])
        if r1 == r2:
            return self.key[r1][(c1 - 1) % 5] + self.key[r2][(c2 - 1) % 5]
        elif c1 == c2:
            return self.key[(r1 - 1) % 5][c1] + self.key[(r2 - 1) % 5][c2]
        else:
            return self.key[r1][c2] + self.key[r2][c1]

    def decrypt(self):
        plain = ""
        for i in range(0, len(self.ciphertext), 2):
            print(self.ciphertext[i : i + 2])
            plain += self.decrypt_pair(self.ciphertext[i : i + 2])
        return plain.lower()


def generate_key_matrix(key):
    key = key.replace(" ", "").upper()
    key_matrix = []
    seen = set()
    for char in key:
        if char not in seen and char.isalpha():
            seen.add(char)
            key_matrix.append(char)
    for char in range(ord("A"), ord("Z") + 1):
        if chr(char) not in seen and chr(char) != "J":
            seen.add(chr(char))
            key_matrix.append(chr(char))
    return [key_matrix[i : i + 5] for i in range(0, len(key_matrix), 5)]


if __name__ == "__main__":
    while True:
        print(
            """<------- Play Fair Cipher Program ------->\n
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
                key = input("Enter the Key: ")
            except ValueError:
                print("Invalid key. Please enter a valid integer.")
                continue
            key_matrix = generate_key_matrix(key)
            cipher = Encode(plaintext, key_matrix)
            print(f"Ciphertext: {cipher.encrypt()}\n")
        elif option == "2":
            print("\n<" + "-" * 20 + "Decoding" + "-" * 20 + ">\n")
            ciphertext = input("Enter the Ciphertext: ")
            key = input("Do you Have the key? if not press Enter: ")
            key_matrix = generate_key_matrix(key)
            plain = Decode(ciphertext, key_matrix)
            print(f"Plaintext : {plain.decrypt()}")

        elif option == "3":
            print("Exiting the program.")
            break
        else:
            print("Invalid option. Please try again.")
