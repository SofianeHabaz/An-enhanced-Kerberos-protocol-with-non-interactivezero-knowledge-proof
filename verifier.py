from mod_operations import square_ZnZ
from shared_hash_function import hash_to_bit_vector

class ffs_verifier:
    def __init__(self, n, k, t):
        """
        Initialize the verifier.
        :param n: Agreed upon large integer.
        :param k: Key size.
        :param t: Number of challenges.
        """
        self.n = n
        self.k = k
        self.t = t
        self.pub_key = None

    def verify(self, x, y, pub_key):
        """
        Verify the client's response to the FFS challenge.
        :param x: The commitment value X_z.
        :param y: The response value Y_z.
        :return: True if the verification succeeds, False otherwise.
        """
        self.pub_key=pub_key
        b = hash_to_bit_vector(x, self.k)
        expected_x = square_ZnZ(y, self.n)
        for i in range(self.k):
            if b[i]:
                expected_x *= self.pub_key[i]
        expected_x = expected_x % self.n
        return expected_x == x

    def set_public_key(self, pub_key):
        """
        Set the public key of the prover.
        :param pub_key: The public key as a list of integers.
        """
        self.pub_key = pub_key