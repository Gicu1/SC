import random
import string

def generate_random_text(file_path, size_gb=3.8):
    """Generate a file with random text of specified size in GB."""
    total_bytes = int(size_gb * 1024 * 1024 * 1024)
    
    chars = string.ascii_letters + string.digits + string.punctuation + ' ' * 10
    
    chunk_size = 1024 * 1024  
    
    bytes_written = 0
    with open(file_path, 'w', encoding='utf-8') as f:
        while bytes_written < total_bytes:
            chunk = ''.join(random.choice(chars) for _ in range(min(chunk_size, total_bytes - bytes_written)))
            f.write(chunk)
            bytes_written += len(chunk.encode('utf-8'))
            
            if bytes_written % (100 * 1024 * 1024) == 0: 
                print(f"Progress: {bytes_written / (1024**3):.2f} GB / {size_gb} GB")

if __name__ == "__main__":
    file_path = "message.txt"
    sz = 1 
    print(f"Generating {sz} GB of random text in '{file_path}'...")
    generate_random_text(file_path, size_gb=sz)
    print("Done!")