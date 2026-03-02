#import necessary libraries for AES encryption, padding, and timing
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_aes_128(plaintext, key):
    # initialize the AES cipher using key and ECB 
    cipher = AES.new(key, AES.MODE_ECB)
    # pad 
    padded_data = pad(plaintext.encode(), AES.block_size)
    # return ciphertext
    return cipher.encrypt(padded_data)

def run_brute_force(case_name, ciphertext, known_key_part, missing_bytes, original_text):
    # print header
    print(f"\n--- Starting {case_name} ({missing_bytes * 8} bits missing) ---")
    
    # start timer for case X
    start_time = time.time()
    # attempt counter for case X
    attempts = 0
    # calc number of possible combinations (2^bits)
    total_combinations = 2**(8 * missing_bytes)
    
    # flag
    found = False
    
    # start brute force loop
    for i in range(total_combinations):
        # calculate elapsed time for this attempt
        current_elapsed = time.time() - start_time
        # increment attempt counter
        attempts += 1
        
        # check for timeout (30 minutes = 1800 seconds)
        if current_elapsed > 1800:
            print(f"\n[!] TIMEOUT: Limit reached at {current_elapsed:.2f}s. Ending search.")
            break

        # update the console 
        # every 1000 attempts to show progress without slowing down the CPU
        if attempts % 1000 == 0 or missing_bytes == 1:
            # print the current attempt, elapsed time, and the current key guess in hex format (only the missing part)
            print(f"Attempt #{attempts} | Time Elapsed: {current_elapsed:.2f}s | Key: {i:0{missing_bytes*2}X}", end='\r')

        # convert the current loop integer into the missing byte sequence (big-endian)
        missing_part = i.to_bytes(missing_bytes, 'big')
        # known part + missing part = trial key
        trial_key = known_key_part + missing_part
        
        try:
            # new AES cipher object with the trial key
            cipher = AES.new(trial_key, AES.MODE_ECB)
            # decrypt the ciphertext
            raw_decrypted = cipher.decrypt(ciphertext)
            # try remove padding, throws error if key is wrong
            decrypted = unpad(raw_decrypted, AES.block_size).decode()
            
            # check if decrypted text matches original
            if decrypted == original_text:
                found = True
                print(f"\n[!] SUCCESS: Correct key found in {current_elapsed:.2f}s!")
                break
        except (ValueError, KeyError, UnicodeDecodeError):
            # if decryption fails or any erorr occurs, go next
            continue

    # stop timer for case X
    end_time = time.time()
    duration = end_time - start_time
    
    # print all results for case X
    print(f"Final Status: {'Success' if found else 'Failed/Timed Out'}")
    print(f"Total Time Recorded: {duration:.2f} seconds")
    print(f"Total Attempts Made: {attempts}")
    return found, duration, attempts


# paragraph to be used for this assignment simulation
paragraph = "The goal of this assignment is to help you understand the strength of AES-128 encryption by simulating a brute force attack under different scenarios. You will implement AES-128 encryption and decryption, generate a random key, and measure the time it takes to brute force a partially known key." # You can replace this with any text you'd like to test with.
# Generate a secure random 128-bit key (16 bytes) 
true_key = get_random_bytes(16) 
# Encrypt the paragraph using the key
ciphertext = encrypt_aes_128(paragraph, true_key)

# program start
print("="*50) # separator for clarity
print("AES-128 BRUTE FORCE SIMULATION DATA")
print("="*50)
print(f"Original Text: {paragraph}") #og text
print(f"Original Key (Hex): {true_key.hex().upper()}") #og key in hex 
print(f"Ciphertext (Hex): {ciphertext.hex().upper()}") #ciphertext in hex 
print("="*50)

# three test cases (8-bit, 32-bit, and 64-bit)
scenarios = [("Case 1", 1), ("Case 2", 4), ("Case 3", 8)]

# loop to run each case
for name, count in scenarios:
    # create partial key by removing the last count bytes from the true key
    known_part = true_key[:-count]
    # run given all info for case X
    run_brute_force(name, ciphertext, known_part, count, paragraph)