import threading
from kerberos_kdc import KerberosKDC
from kerberos_client import KerberosClient

# Parameters for FFS
n = 101  # Large integer (use a secure prime in a real system)
k = 8    # Key size
t = 5    # Number of challenges

# Start the KDC in a separate thread
def start_kdc():
    kdc = KerberosKDC(n, k, t)
    kdc.listen(42424)

# Start the KDC thread
kdc_thread = threading.Thread(target=start_kdc)
kdc_thread.start()

# Wait for the KDC to start listening
import time
time.sleep(2)

# Start the Kerberos Client
client = KerberosClient(n, k)
client.send_krb_as_req("127.0.0.1", 42424)

# Wait for the KDC thread to finish
kdc_thread.join()