import random
from mod_operations import inverse, square_ZnZ
from shared_hash_function import hash_to_bit_vector

class ffs_prover:
    def __init__(self, n, k):
        """
        Initialize the prover's key.
        :param n: Agreed upon large integer.
        :param k: Key size.
        """
        self.n = n
        self.k = k
        self.s = [None] * k  # Private key
        self.p = [None] * k  # Public key
        for i in range(k):
            self.s[i] = random.randint(0, n - 1)
            self.p[i] = inverse(square_ZnZ(self.s[i], n), n) % n
            self.p[i] = int(self.p[i])
        print("Prover initialized...")
        print("\tPrivate key: " + ",".join(map(str, self.s)))
        print("\tPublic key: " + ",".join(map(str, self.p)))

    def generate_commitment(self):
        """
        Generate a commitment (X_z, Y_z) for the FFS protocol.
        :return: A tuple (x, y) representing the commitment.
        """
        r = random.randint(0, self.n - 1)
        x = square_ZnZ(r, self.n) % self.n
        b = hash_to_bit_vector(x, self.k)
        y = r
        for i in range(self.k):
            if b[i]:
                y *= self.s[i]
        y = y % self.n
        return x, y, self.get_public_key()

    def get_public_key(self):
        """
        Get the public key of the prover.
        :return: The public key as a list of integers.
        """
        return self.p