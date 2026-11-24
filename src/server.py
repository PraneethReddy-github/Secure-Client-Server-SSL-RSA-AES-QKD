import socket
import os
import sys
import threading
import ssl
import random
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# --- Path Resolution Helpers ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(BASE_DIR, "certs")
CERT_FILE = os.path.join(CERTS_DIR, "server.crt")
KEY_FILE = os.path.join(CERTS_DIR, "server.key")

# --- Reliable TCP Socket Recv Helper ---
def recv_exact(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)

# --- S/MIME Email Notification Function ---
def send_email_notification(subject, body):
    sender_email = os.environ.get("SENDER_EMAIL", "")
    sender_password = os.environ.get("SENDER_PASSWORD", None)
    receiver_email = os.environ.get("RECEIVER_EMAIL", "")

    if not sender_password or sender_password == "YOUR_PASSWORD_HERE":
        print("[NOTIF] S/MIME email notification skipped (SENDER_PASSWORD environment variable not configured).")
        return

    try:
        if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
            print("[NOTIF] Skip S/MIME email (Certificates not found).")
            return

        with open(CERT_FILE, "rb") as cert_f:
            cert_data = cert_f.read()
        with open(KEY_FILE, "rb") as key_f:
            private_key_data = key_f.read()

        private_key = load_pem_private_key(private_key_data, password=None, backend=default_backend())

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Sign email payload with S/MIME PKCS1v15 + SHA256
        signature = private_key.sign(
            body.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        signature_attachment = MIMEApplication(signature, _subtype='pkcs7-signature')
        signature_attachment.add_header('Content-Disposition', 'attachment', filename='smime.p7s')
        msg.attach(signature_attachment)

        server = smtplib.SMTP('smtp.office365.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print(f"[NOTIF] S/MIME signed email notification sent to {receiver_email}.")
    except Exception as e:
        print(f"[NOTIF ERROR] Failed to send email notification: {e}")


# --- BB84 Quantum Key Distribution (QKD) Protocol Simulation ---
def qkd_key_exchange(client_socket):
    print("\n[QKD] Initiating BB84 Quantum Key Exchange Simulation...")
    key_size = 128
    
    # 1. Server generates random photon bases (0 = Rectilinear +, 1 = Diagonal x) & bits
    server_bases = [random.randint(0, 1) for _ in range(key_size)]
    server_bits = [random.randint(0, 1) for _ in range(key_size)]
    
    # Transmit bases and bits over secure channel
    client_socket.sendall(bytes(server_bases))
    client_socket.sendall(bytes(server_bits))
    
    # 2. Receive Client's measurement bases
    client_bases_raw = recv_exact(client_socket, key_size)
    if not client_bases_raw:
        raise Exception("QKD failed: Client disconnected during basis exchange.")
    client_bases = list(client_bases_raw)
    
    # 3. Sift bases: keep bits where bases match
    sifted_key = []
    for i in range(key_size):
        if server_bases[i] == client_bases[i]:
            sifted_key.append(server_bits[i])
    
    sifted_key_str = ''.join(map(str, sifted_key[:len(sifted_key)//2]))
    print(f"[QKD SUCCESS] Negotiated Quantum Secret Key (Sifted): {sifted_key_str[:32]}...")
    
    return bytes(sifted_key[:len(sifted_key)//2])


# --- Client Session Handler ---
clients = {}

def handle_client(client_socket, client_address, client_id):
    start_time = datetime.now()
    try:
        print(f"\n[CLIENT CONNECTED] Address: {client_address} | Assigned Client ID: {client_id}")

        send_email_notification(
            subject="Secure Server Alert: New Client Connected",
            body=f"Client Connected:\nAddress: {client_address}\nClient ID: {client_id}\nTime: {start_time}"
        )
        
        # 1. Execute Quantum Key Distribution (BB84 Protocol)
        qkd_key = qkd_key_exchange(client_socket)
        print(f"[CLIENT {client_id}] QKD Negotiated Key (Hex): {qkd_key.hex()}")
        
        # 2. Generate Server RSA-2048 Key Pair
        server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_public_key = server_private_key.public_key()
        
        server_public_pem = server_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.sendall(server_public_pem)
        
        # 3. Receive Client's RSA Public Key
        client_public_pem = recv_exact(client_socket, 451) # 2048-bit SubjectPublicKeyInfo PEM is 451 bytes
        if not client_public_pem:
            # Fallback if size varies slightly
            client_public_pem = client_socket.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_pem)
        
        clients[client_id] = (client_socket, server_private_key, client_public_key, qkd_key)
        print(f"[CLIENT {client_id}] SSL + QKD + RSA Handshake Complete. Ready for encrypted messaging.")
        
        # 4. Message Handling Loop
        while True:
            raw_data = client_socket.recv(4096)
            if not raw_data:
                break

            raw_message = raw_data.decode('utf-8')
            if ':' in raw_message:
                parts = raw_message.split(':', 2)
                if len(parts) < 3:
                    client_socket.sendall("Error: Invalid payload format.".encode('utf-8'))
                    continue

                recipient_id, encrypted_hex, signature_hex = parts
                encrypted_data = bytes.fromhex(encrypted_hex)
                signature = bytes.fromhex(signature_hex)
                
                print(f"\n[CLIENT {client_id} -> RECIPIENT {recipient_id}] Encrypted Payload Received ({len(encrypted_data)} bytes)")
                
                # A. Verify RSA PSS Digital Signature using Client Public Key
                try:
                    sender_pub_key = clients[client_id][2]
                    sender_pub_key.verify(
                        signature,
                        encrypted_data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    print(f"[CLIENT {client_id}] RSA PSS Digital Signature VERIFIED (Integrity & Authenticity Confirmed).")
                except Exception as sig_err:
                    client_socket.sendall("Security Error: Signature verification failed!".encode('utf-8'))
                    print(f"[SECURITY ALERT] Signature Verification Failed for Client {client_id}: {sig_err}")
                    continue

                # B. Decrypt AES Key using Server's RSA Private Key (OAEP + SHA256)
                iv = encrypted_data[:16]
                encrypted_aes_key = encrypted_data[16:16 + 256]
                encrypted_payload = encrypted_data[16 + 256:]

                aes_key = server_private_key.decrypt(
                    encrypted_aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                # C. Decrypt Message Payload using AES-256-CFB
                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_message = (decryptor.update(encrypted_payload) + decryptor.finalize()).decode('utf-8')

                print(f"[DECRYPTED CONTENT] Client {client_id} sent: '{decrypted_message}'")

                # D. Forward Decrypted Message to Target Recipient
                if recipient_id in clients:
                    recipient_socket = clients[recipient_id][0]
                    recipient_socket.sendall(f"From Client {client_id}: {decrypted_message}".encode('utf-8'))
                    print(f"[ROUTING] Message forwarded to Client ID {recipient_id}")
                else:
                    client_socket.sendall(f"Error: Recipient ID '{recipient_id}' not online.".encode('utf-8'))
            else:
                client_socket.sendall("Error: Invalid message format. Use 'recipient_id:encrypted_data:signature'.".encode('utf-8'))

    except Exception as err:
        print(f"[CLIENT DISCONNECT / ERROR] Client {client_id}: {err}")
    finally:
        end_time = datetime.now()
        duration = end_time - start_time
        print(f"\n[CLIENT DISCONNECTED] Address: {client_address} | ID: {client_id} | Session Duration: {duration}")

        send_email_notification(
            subject="Secure Server Alert: Client Disconnected",
            body=f"Client Disconnected:\nAddress: {client_address}\nClient ID: {client_id}\nDuration: {duration}"
        )

        if client_id in clients:
            del clients[client_id]
        client_socket.close()


# --- Main Server Entry Point ---
def main():
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print(f"Error: Certificate or key missing at '{CERTS_DIR}'. Please run ./scripts/generate_certs.sh.")
        sys.exit(1)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_socket.bind(('0.0.0.0', 9999))
    raw_socket.listen(5)

    ssl_server_socket = context.wrap_socket(raw_socket, server_side=True)

    print("==========================================================================")
    print("  Unified Secure Client-Server System (SSL/TLS + QKD + Hybrid RSA-AES)")
    print("==========================================================================")
    print("Server initialized and listening securely on port 9999...")

    client_counter = 1
    try:
        while True:
            client_sock, client_addr = ssl_server_socket.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr, str(client_counter)))
            t.daemon = True
            t.start()
            client_counter += 1
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        ssl_server_socket.close()

if __name__ == "__main__":
    main()
