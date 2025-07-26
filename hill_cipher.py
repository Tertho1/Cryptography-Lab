import math
import numpy as np
import sympy as sp


class Encode:
    def __init__(self, plaintext, key):
        self.plaintext = plaintext.lower().replace(" ", "")
        self.key = key

    def create_block(self):
        rem = len(self.plaintext) % len(self.key)
        self.plaintext += "z" * rem
        pt = []
        for i in range(0, len(self.plaintext)):
            pt.append(ord(self.plaintext[i]) - ord("a"))
        return [pt[i : i + len(self.key)] for i in range(0, len(pt), len(self.key))]

    def encrypt(self):
        ciphertext = ""
        modified_plaintext = np.array(self.create_block())
        ct = np.dot(modified_plaintext, self.key) % 26
        # print("Modified Plaintext:", modified_plaintext)
        # for text in modified_plaintext:
        # print("Ciphertext Matrix:", ct)
        for row in ct:
            for val in row:
                ciphertext += chr(val + ord("a"))
        # print("Ciphertext:", ciphertext)
        return ciphertext.upper()


class Decode:
    def __init__(self, ciphertext, key):
        self.ciphertext = ciphertext.upper().replace(" ", "")
        self.key = key

    def create_block(self):
        rem = len(self.ciphertext) % len(self.key)
        self.ciphertext += "Z" * rem
        ct = []
        for i in range(0, len(self.ciphertext)):
            ct.append(ord(self.ciphertext[i]) - ord("A"))
        return [ct[i : i + len(self.key)] for i in range(0, len(ct), len(self.key))]

    def get_inv_matrix(self):
        try:
            inv_key = sp.Matrix(self.key).inv_mod(26)
            return np.array(inv_key).astype(int)    
        except:
            raise ValueError("Matrix is not invertible under modulo 26")
    def get_inv_matrix_old(self):
        det = int(round(np.linalg.det(self.key))) % 26
        print("Determinant:", det)
        det_inv = None
        for i in range(1, 26):
            if (det * i) % 26 == 1:
                det_inv = i
                break
        if det_inv is None:
            raise ValueError("Matrix is not invertible under modulo 26")

        cofactors = np.zeros(self.key.shape)
        for r in range(self.key.shape[0]):
            for c in range(self.key.shape[1]):
                minor = np.delete(np.delete(self.key, r, axis=0), c, axis=1)
                cofactors[r, c] = ((-1) ** (r + c)) * round(np.linalg.det(minor))

        adjugate = np.transpose(cofactors)
        inv = (det_inv * adjugate) % 26

        return inv.astype(int)

    def decrypt(self):
        plain = ""
        # print(self.key)
        inv_key = self.get_inv_matrix()
        # inv_key = np.round(inv_key).astype(int) % 26
        # print("Inverse Key Matrix:", inv_key)
        modified_ciphertext = np.array(self.create_block())
        # print("Modified Ciphertext:", modified_ciphertext)
        ct = np.dot(modified_ciphertext, inv_key) % 26
        for row in ct:
            for val in row:
                plain += chr(val + ord("a"))
        return plain.lower()


def generate_key_matrix(key):
    k = int(math.sqrt(len(key)))
    if k * k != len(key):
        print("Key length must be a perfect square.")

    key = key.replace(" ", "").upper()
    key_matrix = []
    for char in key:
        if char.isalpha():
            key_matrix.append(ord(char) - ord("A"))
    return np.array([key_matrix[i : i + k] for i in range(0, len(key_matrix), k)])


if __name__ == "__main__":
    while True:
        print(
            """<------- Hill Cipher Program ------->\n
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

            key_matrix = np.array(generate_key_matrix(key))
            # print(len(key_matrix))
            # print("Key Matrix:", key_matrix)
            cipher = Encode(plaintext, key_matrix)
            print(f"Ciphertext: {cipher.encrypt()}\n")
        elif option == "2":
            print("\n<" + "-" * 20 + "Decoding" + "-" * 20 + ">\n")
            ciphertext = input("Enter the Ciphertext: ")
            key = input("Enter the key: ")
            key_matrix = generate_key_matrix(key)
            # print("Key Matrix:", key_matrix)
            plain = Decode(ciphertext, key_matrix)
            print(f"Plaintext : {plain.decrypt()}")

        elif option == "3":
            print("Exiting the program.")
            break
        else:
            print("Invalid option. Please try again.")
