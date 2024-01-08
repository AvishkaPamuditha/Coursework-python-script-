import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode())

def rsa_decrypt(private_key, encrypted_message):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_message).decode()

def create_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

def create_signature(private_key, message):
    private_key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return signature

def verify_signature(public_key, message, signature):
    public_key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Generate RSA keys
robot_private_key, robot_public_key = generate_keys()
cloud_private_key, cloud_public_key = generate_keys()

# User input
message = input("Enter the health data message: ")

# Encrypt, Decrypt, and Hash
encrypted_message = rsa_encrypt(cloud_public_key, message)
decrypted_message = rsa_decrypt(cloud_private_key, encrypted_message)
message_hash = create_hash(message)
decrypted_hash = create_hash(decrypted_message)

# Digital Signature
signature = create_signature(robot_private_key, message)
signature_valid = verify_signature(robot_public_key, message, signature)

# Output
print("\nOriginal Message:", message)
print("Encrypted Message:", encrypted_message.hex())
print("Decrypted Message:", decrypted_message)
print("Original Hash:", message_hash)
print("Decrypted Hash:", decrypted_hash)
print("Signature Valid:", signature_valid)
