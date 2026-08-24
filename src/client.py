import socket
import os
import sys
import threading
import ssl
import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- Path Resolution Helpers ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
CERT_FILE = os.path.join(CERTS_DIR, "server.crt")

# --- QKD Key Exchange (Client Side) ---
def qkd_key_exchange(client_socket):
    key_size = 128
    
    server_bases = list(client_socket.recv(key_size))
    server_bits = list(client_socket.recv(key_size))
    
    client_bases = [random.randint(0, 1) for _ in range(key_size)]
    client_socket.sendall(bytes(client_bases))
    
    shared_key = []
    for i in range(key_size):
        if client_bases[i] == server_bases[i]:
            shared_key.append(server_bits[i])
            
    return bytes(shared_key[:len(shared_key)//2])

def receive_messages(client_socket):
    try:
        while True:
            raw_data = client_socket.recv(4096)
            if raw_data:
                print(f"\n[INCOMING MESSAGE] {raw_data.decode('utf-8')}")
                print("You: ", end="", flush=True)
            else:
                break
    except Exception as e:
        print(f"\n[DISCONNECTED] Connection closed by server: {e}")

def send_messages(client_socket, private_key, server_public_key):
    try:
        while True:
            recipient_id = input("\nEnter recipient ID (e.g., 1, 2): ").strip()
            if not recipient_id:
                continue

            message = input("You: ").strip()
            if not message:
                continue

            # 1. Generate one-time symmetric AES-256 key & IV
            aes_key = os.urandom(32)
            iv = os.urandom(16)

            # 2. Encrypt message content with AES-256-CFB
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

            # 3. Encrypt AES key using Server's RSA Public Key (OAEP + SHA256)
            encrypted_aes_key = server_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Assemble full encrypted payload: IV (16) + Encrypted AES Key (256) + Ciphertext
            full_encrypted_data = iv + encrypted_aes_key + encrypted_message

            # 4. Generate RSA Digital Signature over payload (PSS + SHA256)
            signature = private_key.sign(
                full_encrypted_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # 5. Format & transmit wire payload
            wire_payload = f"{recipient_id}:{full_encrypted_data.hex()}:{signature.hex()}"
            client_socket.sendall(wire_payload.encode('utf-8'))
            print(f"[SENT] Encrypted payload & digital signature transmitted to Recipient {recipient_id}.")

    except Exception as e:
        print(f"[SEND ERROR] Error sending message: {e}")

def main():
    print("==========================================================================")
    print("  Secure Client Interface (SSL/TLS + Hybrid RSA-AES Encryption)")
    print("==========================================================================")

    if not os.path.exists(CERT_FILE):
        print(f"Warning: '{CERT_FILE}' missing. SSL verification might fail.")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    
    if os.path.exists(CERT_FILE):
        context.load_verify_locations(CERT_FILE)

    server_ip = input("Enter Server IP Address (default 127.0.0.1): ").strip()
    if not server_ip:
        server_ip = "127.0.0.1"

    server_port = 9999
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        ssl_client_socket = context.wrap_socket(raw_socket, server_hostname=server_ip)
        ssl_client_socket.connect((server_ip, server_port))
        print(f"[CONNECTED] Established SSL/TLS connection to server at {server_ip}:{server_port}")
    except Exception as conn_err:
        print(f"Error connecting to server: {conn_err}")
        sys.exit(1)

    # 1. Quantum Key Exchange (BB84 Simulation)
    qkd_symmetric_key = qkd_key_exchange(ssl_client_socket)
    print(f"[QKD] Shared Quantum Key (Hex): {qkd_symmetric_key.hex()}")

    # 2. RSA Key Pair Generation for Client
    client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client_public_key = client_private_key.public_key()

    # 3. Exchange Public Keys with Server
    server_public_pem = ssl_client_socket.recv(2048)
    server_public_key = serialization.load_pem_public_key(server_public_pem)

    client_public_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ssl_client_socket.sendall(client_public_pem)
    print("[HANDSHAKE] RSA Public Keys Exchanged Successfully. Secure Channel Ready.")

    # Start threads for bidirectional messaging
    recv_thread = threading.Thread(target=receive_messages, args=(ssl_client_socket,))
    recv_thread.daemon = True
    recv_thread.start()

    send_messages(ssl_client_socket, client_private_key, server_public_key)

if __name__ == "__main__":
    main()
