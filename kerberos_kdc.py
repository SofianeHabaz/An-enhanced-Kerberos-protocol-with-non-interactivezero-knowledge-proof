import json
import socket
import os
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from verifier import ffs_verifier

class KerberosKDC:
    def __init__(self, n, k, t):
        self.ffs_verifier = ffs_verifier(n, k, t)
        # Load KDC's private key
        with open("kdc_private_key.pem", "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        # Hardcode a secret key for encrypting TGTs (in practice, use a secure key)
        self.kdc_secret_key = os.urandom(32)  # 256-bit key

    def generate_tgt(self, client_id, session_key):
        """
        Generate a Ticket Granting Ticket (TGT) for the client.
        """
        # Create TGT data
        tgt_data = {
            "client_id": client_id,
            "session_key": session_key.hex(),
            "timestamp": int(time.time()),  # Current time
            "expiration": int(time.time()) + 3600,  # Expires in 1 hour
            "tgs_id": "TGS_1"  # Hardcoded TGS ID
        }
        # Serialize TGT data to bytes
        tgt_bytes = self.serialize_tgt(tgt_data)
        # Encrypt TGT using KDC's secret key
        encrypted_tgt = self.encrypt_tgt(tgt_bytes)
        return encrypted_tgt

    def serialize_tgt(self, tgt_data):
        """
        Serialize TGT data into a byte string.
        """
        return (
            f"ClientID:{tgt_data['client_id']},"
            f"SessionKey:{tgt_data['session_key']},"
            f"Timestamp:{tgt_data['timestamp']},"
            f"Expiration:{tgt_data['expiration']},"
            f"TGSID:{tgt_data['tgs_id']}"
        ).encode()

    def encrypt_tgt(self, tgt_bytes):
        """
        Encrypt the TGT using the KDC's secret key.
        """
        # Use AES encryption for simplicity
        iv = os.urandom(16)  # Initialization vector
        cipher = Cipher(algorithms.AES(self.kdc_secret_key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_tgt = iv + encryptor.update(tgt_bytes) + encryptor.finalize()
        return encrypted_tgt

    def process_krb_as_req(self, encrypted_data):
        """
        Process the KRB_AS_REQ message from the client.
        """
        # Decrypt the data using KDC's private key
        decrypted_data = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Extract K_c,as, X_z, Y_z
        k_c_as,x_z_bytes,y_z_bytes, ffs_public_key = decrypted_data.split(b"||")
        # k_c_as = decrypted_data[:32]  # Assuming 256-bit key
        # x_z_bytes = decrypted_data[32:64]
        # y_z_bytes = decrypted_data[64:]
        print("received data:", decrypted_data)
        print("received session key:", k_c_as)
        print("received x_z_bytes:", x_z_bytes)
        print("received y_z_bytes:", y_z_bytes)
        # Convert x_z and y_z back to integers
        x_z = int.from_bytes(x_z_bytes, 'big')
        y_z = int.from_bytes(y_z_bytes, 'big')
        ffs_public_key=json.loads(ffs_public_key.decode())
        # Verify X_z and Y_z using FFS
        if self.ffs_verifier.verify(x_z, y_z, ffs_public_key):
            # Generate TGT and session key K_c,tgs
            tgt = self.generate_tgt("client_1", k_c_as)  # Replace "client_1" with actual client ID
            k_c_tgs = Fernet.generate_key()
            # Format the KRB_AS_REP message
            krb_as_rep_message = tgt + b"||" + k_c_tgs
            # Encrypt the KRB_AS_REP message using K_c,as
            cipher_suite = Fernet(k_c_as)
            print("fernet kdc:",cipher_suite)
            encrypted_response = cipher_suite.encrypt(krb_as_rep_message)
            print("encrypted_response kds",encrypted_response)
            return encrypted_response
        else:
            raise Exception("Authentication failed")

    def listen(self, port):
        """
        Listen for client connections.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sersock:
            sersock.bind(('127.0.0.1', port))
            sersock.listen(1)
            print(f"KDC listening on port {port}...")
            while True:
                conn, addr = sersock.accept()
                with conn:
                    print(f"Connected by {addr}")
                    data = conn.recv(1024)
                    try:
                        response = self.process_krb_as_req(data)
                        conn.sendall(response)
                    except Exception as e:
                        conn.sendall(f"ERROR:{str(e)}".encode())