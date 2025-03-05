import json
import socket
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from prover import ffs_prover
import sys
class KerberosClient:
    def __init__(self, n, k):
        self.ffs_prover = ffs_prover(n, k)  # Initialize FFS prover
        self.client_id = "client_1"
        self.session_key = None

    def generate_krb_as_req(self, kdc_public_key):
        """
        Generate the KRB_AS_REQ message.
        """
        # Generate session key K_c,as
        self.session_key = Fernet.generate_key()  # This is already bytes
        # Generate X_z and Y_z using FFS
        x_z, y_z, ffs_public_key = self.ffs_prover.generate_commitment()
        # Convert x_z and y_z to bytes
        x_z_bytes = x_z.to_bytes((x_z.bit_length() + 7) // 8, 'big')  # Convert int to bytes
        y_z_bytes = y_z.to_bytes((y_z.bit_length() + 7) // 8, 'big')  # Convert int to bytes
        # Encrypt K_c,as, X_z, Y_z using KDC's public key
        print("sent session key:", self.session_key)
        print(sys.getsizeof(self.session_key))
        print("sent x_z_bytes:", x_z_bytes)
        print("sent y_z_bytes:", y_z_bytes)
        print("sent data:", self.session_key + x_z_bytes + y_z_bytes)

        encrypted_data = kdc_public_key.encrypt(
            self.session_key + b"||" + x_z_bytes + b"||" + y_z_bytes + b"||" + json.dumps(ffs_public_key).encode(),  # Concatenate bytes
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_data

    def send_krb_as_req(self, kdc_address, kdc_port):
        """
        Send the KRB_AS_REQ message to the KDC.
        """
        # Load KDC's public key
        with open("kdc_public_key.pem", "rb") as key_file:
            kdc_public_key = serialization.load_pem_public_key(key_file.read())
        # Generate KRB_AS_REQ
        encrypted_data = self.generate_krb_as_req(kdc_public_key)
        # Send KRB_AS_REQ to KDC
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((kdc_address, kdc_port))
            sock.sendall(encrypted_data)
            # Receive KRB_AS_REP
            response = sock.recv(1024)
            print('received response:', response)
            self.process_krb_as_rep(response)

    def process_krb_as_rep(self, encrypted_response):
        """
        Process the KRB_AS_REP message from the KDC.
        """
        print("encrypted_response client",encrypted_response)
        # Decrypt the response using session key K_c,as
        cipher_suite = Fernet(self.session_key)
        print("fernet client:",cipher_suite)
        decrypted_response = cipher_suite.decrypt(encrypted_response)
        # Extract TGT and session key K_c,tgs
        tgt, k_c_tgs = decrypted_response.split(b"||")
        print(f"Received TGT: {tgt.hex()}")
        print(f"Received Session Key: {k_c_tgs.hex()}")