import socket
import ssl
import time
import subprocess
import sys
import os
import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT_FILE = os.path.join(BASE_DIR, "certs", "server.crt")

def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

def run_client_handshake(sock):
    key_size = 128
    server_bases_raw = recv_exact(sock, key_size)
    server_bits_raw = recv_exact(sock, key_size)
    server_bases = list(server_bases_raw)
    server_bits = list(server_bits_raw)
    
    client_bases = [random.randint(0, 1) for _ in range(key_size)]
    sock.sendall(bytes(client_bases))
    
    sifted_key = []
    for i in range(key_size):
        if client_bases[i] == server_bases[i]:
            sifted_key.append(server_bits[i])
    qkd_key = bytes(sifted_key[:len(sifted_key)//2])

    # RSA Key Pair Generation
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_public_key = client_private_key.public_key()

    server_public_pem = sock.recv(2048)
    server_public_key = serialization.load_pem_public_key(server_public_pem)

    client_public_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sock.sendall(client_public_pem)

    return client_private_key, server_public_key, qkd_key

def main():
    print("--- Starting End-to-End Cryptographic Integration Test ---")
    
    # 1. Start Server in background
    server_proc = subprocess.Popen(
        [sys.executable, os.path.join(BASE_DIR, "src", "server.py")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(2)  # Allow server to bind port

    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(CERT_FILE)

        # Connect Client 1 (ID 1)
        raw_sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1 = context.wrap_socket(raw_sock1, server_hostname="127.0.0.1")
        sock1.connect(("127.0.0.1", 9999))
        c1_priv, c1_serv_pub, c1_qkd = run_client_handshake(sock1)
        print("[TEST] Client 1 Handshake Complete. QKD Key len:", len(c1_qkd))

        # Connect Client 2 (ID 2)
        raw_sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2 = context.wrap_socket(raw_sock2, server_hostname="127.0.0.1")
        sock2.connect(("127.0.0.1", 9999))
        c2_priv, c2_serv_pub, c2_qkd = run_client_handshake(sock2)
        print("[TEST] Client 2 Handshake Complete. QKD Key len:", len(c2_qkd))

        # Send test message from Client 1 to Client 2
        test_message = "Hello, Client 2! Testing SSL + QKD + RSA-AES Hybrid Security."
        aes_key = os.urandom(32)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(test_message.encode('utf-8')) + encryptor.finalize()

        encrypted_aes_key = c1_serv_pub.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        full_encrypted_data = iv + encrypted_aes_key + encrypted_message

        signature = c1_priv.sign(
            full_encrypted_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        payload = f"2:{full_encrypted_data.hex()}:{signature.hex()}"
        sock1.sendall(payload.encode('utf-8'))
        print("[TEST] Client 1 payload transmitted to Client 2.")

        # Receive on Client 2
        sock2.settimeout(3.0)
        received_data = sock2.recv(4096).decode('utf-8')
        print(f"[TEST] Client 2 Received: '{received_data}'")

        assert "Hello, Client 2!" in received_data, "Test Failed: Message content mismatch!"
        print("\n==================================================")
        print("  ALL INTEGRATION TESTS PASSED 100% SUCCESSFULLY!")
        print("==================================================")

        sock1.close()
        sock2.close()

    finally:
        server_proc.terminate()
        server_proc.wait()

if __name__ == "__main__":
    main()
