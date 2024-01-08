import ecdsa
import hashlib
import base58
import random
import winsound

def generate_random_hex():
    # Define the range of numbers
    lower_bound = 36893488147419103231
    #lower_bound = 56893488147419103231
    upper_bound = 73786976294838206463

    # Generate a random number within the specified range
    random_number = random.randint(lower_bound, upper_bound)

    # Convert the random number to a 64-digit hexadecimal representation
    hex_representation = hex(random_number)[2:].zfill(64)

    return hex_representation

def private_key_to_wif_and_address(private_key_hex, compressed=True):
    # Convert hex private key to bytes
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Create an ECDSA signing key using the private key
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)

    # Get the corresponding verifying key (public key)
    verifying_key = signing_key.get_verifying_key()

    # Determine if the public key should be compressed
    if compressed:
        public_key_bytes = verifying_key.to_string("compressed")
    else:
        public_key_bytes = verifying_key.to_string("uncompressed")

    # SHA-256 hash of the public key
    sha256_hash = hashlib.sha256(public_key_bytes).digest()

    # RIPEMD-160 hash of the SHA-256 hash
    ripemd160_hash = hashlib.new("ripemd160")
    ripemd160_hash.update(sha256_hash)
    public_key_hash = ripemd160_hash.digest()

    # Add the version byte for the mainnet (0x00) to the public key hash
    extended_public_key = b"\x00" + public_key_hash

    # Double SHA-256 hash of the extended public key
    sha256_hash = hashlib.sha256(extended_public_key).digest()
    sha256_hash = hashlib.sha256(sha256_hash).digest()

    # Add the first 4 bytes of the double SHA-256 hash as a checksum
    checksum = sha256_hash[:4]
    extended_public_key_with_checksum = extended_public_key + checksum

    # Base58 encode the extended public key with checksum (Bitcoin address)
    bitcoin_address = base58.b58encode(extended_public_key_with_checksum).decode("utf-8")

    # Create the WIF (Wallet Import Format)
    wif_prefix = b"\x80" if not compressed else b"\x80"
    wif_data = wif_prefix + private_key_bytes + (b"\x01" if compressed else b"")
    wif_checksum = hashlib.sha256(hashlib.sha256(wif_data).digest()).digest()[:4]
    wif_with_checksum = wif_data + wif_checksum
    wif = base58.b58encode(wif_with_checksum).decode("utf-8")

    return wif, bitcoin_address

# Example usage
balance = 0
counter = 0
counter2 = 0
while balance == 0:
    counter += 1
    if counter == 1000000:
        counter2 = counter2 + 1000000
        counter = 0
        print (counter2)
    private_key_hex = generate_random_hex()
    wif, bitcoin_address = private_key_to_wif_and_address(private_key_hex)
    if bitcoin_address == "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so":balance = 1
    #if bitcoin_address == "1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9":balance = 1
    #if bitcoin_address == "1MVDYgVaSN6iKKEsbzRUAYFrYJadLYZvvZ":balance = 1
    #if bitcoin_address == "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG":balance = 1
    #print("Private Key:", private_key_hex)
    #print("WIF (Wallet Import Format):", wif)
    #print("Address:", bitcoin_address)
    if balance == 1:
        print("Private Key:", private_key_hex)
        print("WIF (Wallet Import Format):", wif)
        print("Address:", bitcoin_address)
        f = open("Insert You File Path Here2.csv", "a")
        f.write(bitcoin_address + ',' + wif + ',' + private_key_hex + '\n')
        f.close()
        yo = 0
        while yo == 0:
            winsound.Beep(440, 500) # frequency, duration
            winsound.Beep(600, 500)
