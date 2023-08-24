import hashlib
import base64

def hash_md5(input_string):
    return hashlib.md5(input_string.encode()).hexdigest()

def hash_sha1(input_string):
    return hashlib.sha1(input_string.encode()).hexdigest()

def hash_sha256(input_string):
    return hashlib.sha256(input_string.encode()).hexdigest()

def hash_sha512(input_string):
    return hashlib.sha512(input_string.encode()).hexdigest()

def encode_base64(input_string):
    encoded_bytes = base64.b64encode(input_string.encode())
    return encoded_bytes.decode('utf-8')

def identify_hash_or_base64(input_string):
    hash_length = len(input_string)
    
    try:
        decoded_bytes = base64.b64decode(input_string)
        decoded_string = decoded_bytes.decode('utf-8')
        return f"Identified Base64: {decoded_string}"
    except:
        pass
    
    if hash_length == 32:
        return "Possible MD5 hash"
    elif hash_length == 40:
        return "Possible SHA-1 hash"
    elif hash_length == 64:
        return "Possible SHA-256 hash"
    elif hash_length == 128:
        return "Possible SHA-512 hash"
    else:
        return "Unknown format"

print("Choose an option:")
print("1. Guess hash")
print("2. Generate hash")
choice = input("Enter the desired option number: ")

if choice == "1":
    hash_to_guess = input("Enter the hash to guess: ")
    result = identify_hash_or_base64(hash_to_guess)
elif choice == "2":
    data_to_process = input("Enter the data for processing: ")
    print("Choose an option:")
    print("1. Generate MD5")
    print("2. Generate SHA-1")
    print("3. Generate SHA-256")
    print("4. Generate SHA-512")
    print("5. Generate Base64")
    hash_choice = input("Enter the desired option number: ")
    
    if hash_choice == "1":
        result = hash_md5(data_to_process)
    elif hash_choice == "2":
        result = hash_sha1(data_to_process)
    elif hash_choice == "3":
        result = hash_sha256(data_to_process)
    elif hash_choice == "4":
        result = hash_sha512(data_to_process)
    elif hash_choice == "5":
        result = encode_base64(data_to_process)
    else:
        result = "Invalid option"
else:
    result = "Invalid option"

print("Result:", result)
