# cryptography_blockchain_fundamentals.py

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# ==========================================
# Vehicle Registration System
# ==========================================
vehicle_database = {}


# ==========================================
# Generate RSA Public-Private Key Pair
# ==========================================
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()


# ==========================================
# SHA-256 Hash Function
# ==========================================
def generate_sha256():
    message = input("\nEnter message to hash: ")

    sha_signature = hashlib.sha256(message.encode()).hexdigest()

    print("\nSHA-256 Hash:")
    print(sha_signature)


# ==========================================
# Digital Signature Creation
# ==========================================
def create_signature():
    message = input("\nEnter message to sign: ")

    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print("\nDigital Signature Generated Successfully!")
    print("Signature (hex format):")
    print(signature.hex())

    return message, signature


# ==========================================
# Digital Signature Verification
# ==========================================
def verify_signature():
    message = input("\nEnter original message: ")

    signature_hex = input("Enter signature in hex format: ")

    try:
        signature = bytes.fromhex(signature_hex)

        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("\nSignature is VALID.")

    except InvalidSignature:
        print("\nSignature is INVALID.")

    except ValueError:
        print("\nInvalid hex signature format.")

    except Exception as e:
        print("\nError:", str(e))


# ==========================================
# Register Vehicle
# ==========================================
def register_vehicle():
    number_plate = input("\nEnter Number Plate: ").upper()

    # Duplicate Check
    if number_plate in vehicle_database:
        print("Error: Vehicle with this Number Plate already exists.")
        return

    owner = input("Enter Owner Name: ")
    model = input("Enter Vehicle Model: ")

    vehicle_database[number_plate] = {
        "owner": owner,
        "model": model
    }

    print("\nVehicle Registered Successfully!")


# ==========================================
# Retrieve Vehicle
# ==========================================
def retrieve_vehicle():
    number_plate = input("\nEnter Number Plate to Search: ").upper()

    if number_plate in vehicle_database:
        vehicle = vehicle_database[number_plate]

        print("\nVehicle Details")
        print("-----------------------")
        print("Number Plate :", number_plate)
        print("Owner Name   :", vehicle["owner"])
        print("Vehicle Model:", vehicle["model"])

    else:
        print("Error: Vehicle not found.")


# ==========================================
# Display Public Key
# ==========================================
def display_public_key():
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("\nPublic Key:")
    print(pem.decode())


# ==========================================
# Menu System
# ==========================================
def menu():
    while True:
        print("\n====================================")
        print(" Cryptography & Blockchain Fundamentals")
        print("====================================")
        print("1. Generate SHA-256 Hash")
        print("2. Create Digital Signature")
        print("3. Verify Digital Signature")
        print("4. Register Vehicle")
        print("5. Retrieve Vehicle")
        print("6. Display Public Key")
        print("7. Exit")

        choice = input("\nEnter your choice: ")

        if choice == '1':
            generate_sha256()

        elif choice == '2':
            create_signature()

        elif choice == '3':
            verify_signature()

        elif choice == '4':
            register_vehicle()

        elif choice == '5':
            retrieve_vehicle()

        elif choice == '6':
            display_public_key()

        elif choice == '7':
            print("\nExiting Program...")
            break

        else:
            print("\nInvalid choice. Please try again.")


# ==========================================
# Main Program
# ==========================================
if __name__ == "__main__":
    menu()