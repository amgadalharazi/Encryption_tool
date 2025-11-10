import re
import os
import PyPDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import shutil
from pathlib import Path
import json

class SecureFileEncryptor:
    def __init__(self):
        self.key_size = 32  # 256-bit AES
    
    def encrypt_data(self, data, key):
        """Encrypt data using AES-GCM"""
        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes")
        
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode('utf-8')

    def decrypt_data(self, encrypted_data, key):
        """Decrypt data using AES-GCM"""
        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes")
        
        try:
            data = base64.b64decode(encrypted_data)
            if len(data) < 32:  # nonce(16) + tag(16)
                raise ValueError("Invalid encrypted data")
                
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_data
        except (ValueError, KeyError) as e:
            raise ValueError("Decryption failed - invalid key or corrupted data") from e

    def encrypt_file(self, input_path, output_path, key):
        """Encrypt any file"""
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
            
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        
        encrypted = self.encrypt_data(plaintext, key)
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(encrypted)

    def decrypt_file(self, input_path, output_path, key):
        """Decrypt any file"""
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"Input file not found: {input_path}")
            
        with open(input_path, 'r') as f:
            encrypted = f.read()
        
        decrypted = self.decrypt_data(encrypted, key)
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)

    def generate_key(self):
        """Generate a secure random key"""
        return get_random_bytes(self.key_size)

    def save_key(self, key, key_path):
        """Save key to file"""
        os.makedirs(os.path.dirname(key_path) if os.path.dirname(key_path) else '.', exist_ok=True)
        with open(key_path, 'wb') as f:
            f.write(key)

    def load_key(self, key_path):
        """Load key from file"""
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Key file not found: {key_path}")
        with open(key_path, 'rb') as f:
            return f.read()

def get_files_in_input_directory():
    """Get all files in the input directory"""
    input_dir = Path('input')
    if not input_dir.exists():
        return []
    
    files = [f for f in input_dir.iterdir() if f.is_file()]
    return files

def setup_directories():
    """Create necessary directories"""
    directories = ['input', 'output']
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)

def save_file_metadata(files):
    """Save original file names and extensions for proper restoration"""
    metadata = {}
    for file_path in files:
        metadata[file_path.name] = {
            'original_name': file_path.name,
            'extension': file_path.suffix,
            'stem': file_path.stem
        }
    
    metadata_path = Path('output') / 'file_metadata.json'
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    return metadata_path

def load_file_metadata():
    """Load file metadata for proper restoration"""
    metadata_path = Path('output') / 'file_metadata.json'
    if not metadata_path.exists():
        return {}
    
    with open(metadata_path, 'r') as f:
        return json.load(f)

def encrypt_all_files_in_input():
    """Encrypt all files found in the input directory"""
    encryptor = SecureFileEncryptor()
    key = encryptor.generate_key()
    
    files = get_files_in_input_directory()
    if not files:
        print("No files found in the 'input' directory.")
        return None
    
    print(f"Found {len(files)} file(s) in input directory:")
    for i, file_path in enumerate(files, 1):
        print(f"  {i}. {file_path.name} ({file_path.suffix})")
    
    # Save metadata for proper restoration
    metadata_path = save_file_metadata(files)
    
    # Encrypt each file
    encrypted_files = []
    for file_path in files:
        # Create output filename with .encrypted extension
        output_filename = f"{file_path.stem}.encrypted"
        output_path = Path('output') / output_filename
        
        try:
            encryptor.encrypt_file(str(file_path), str(output_path), key)
            encrypted_files.append(output_path)
            print(f"✓ Encrypted: {file_path.name} → {output_path.name}")
        except Exception as e:
            print(f"✗ Failed to encrypt {file_path.name}: {e}")
    
    # Save the key
    key_path = Path('output') / 'key.bin'
    encryptor.save_key(key, str(key_path))
    print(f"\nEncryption key saved: {key_path}")
    print(f"File metadata saved: {metadata_path}")
    
    return key

def decrypt_to_input_directory():
    """Decrypt files back to input directory with original formats"""
    encryptor = SecureFileEncryptor()
    
    # Get key
    key_path = Path('output') / 'key.bin'
    if not key_path.exists():
        print("Error: key.bin not found in 'output' directory.")
        return
    
    # Load file metadata
    metadata = load_file_metadata()
    if not metadata:
        print("Warning: No file metadata found. Files may not restore with correct names.")
    
    try:
        key = encryptor.load_key(str(key_path))
    except Exception as e:
        print(f"Error loading key: {e}")
        return
    
    # Find encrypted files in output directory
    output_dir = Path('output')
    encrypted_files = list(output_dir.glob('*.encrypted'))
    
    if not encrypted_files:
        print("No encrypted files found in 'output' directory.")
        return
    
    print("Found encrypted files:")
    for i, file_path in enumerate(encrypted_files, 1):
        print(f"  {i}. {file_path.name}")
    
    # Decrypt each file with proper original format
    for encrypted_file in encrypted_files:
        # Get original filename from metadata
        original_stem = encrypted_file.stem  # Remove .encrypted extension
        
        # Try to find original filename in metadata
        original_name = None
        for meta in metadata.values():
            if meta['stem'] == original_stem:
                original_name = meta['original_name']
                break
        
        if original_name:
            output_path = Path('input') / original_name
        else:
            # Fallback: use original stem with common extension
            output_path = Path('input') / f"{original_stem}_restored"
            print(f"⚠  No metadata found for {encrypted_file.name}, using generic name: {output_path.name}")
        
        try:
            encryptor.decrypt_file(str(encrypted_file), str(output_path), key)
            print(f"✓ Decrypted: {encrypted_file.name} → {output_path.name}")
            
            # Verify the file is restored properly
            if output_path.exists():
                file_size = output_path.stat().st_size
                print(f"  ↳ Restored file size: {file_size} bytes")
                
        except Exception as e:
            print(f"✗ Failed to decrypt {encrypted_file.name}: {e}")

def encrypt_specific_file():
    """Encrypt a specific file with proper format handling"""
    encryptor = SecureFileEncryptor()
    key = encryptor.generate_key()
    
    input_file = input("Enter file to encrypt: ").strip()
    if not input_file:
        print("No file specified.")
        return
    
    input_path = Path(input_file)
    if not input_path.exists():
        print(f"Error: File '{input_file}' not found.")
        return
    
    # Use original name for encrypted file but with .encrypted extension
    output_filename = f"{input_path.stem}.encrypted"
    output_file = input(f"Enter path to save encrypted file [default: output/{output_filename}]: ").strip()
    output_file = output_file if output_file else f"output/{output_filename}"
    
    key_path = input("Enter path to save key [default: output/key.bin]: ").strip()
    key_path = key_path if key_path else 'output/key.bin'
    
    # Save metadata for single file
    metadata = {
        input_path.name: {
            'original_name': input_path.name,
            'extension': input_path.suffix,
            'stem': input_path.stem
        }
    }
    metadata_path = Path('output') / 'file_metadata.json'
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    encryptor.encrypt_file(str(input_path), output_file, key)
    encryptor.save_key(key, key_path)
    
    print("File encrypted successfully!")
    print(f"Original: {input_path.name} ({input_path.suffix})")
    print(f"Encrypted: {output_file}")
    print(f"Key saved: {key_path}")

def decrypt_specific_file():
    """Decrypt a specific file with proper format handling"""
    encryptor = SecureFileEncryptor()
    
    key_path = input("Enter key file path: ").strip()
    encrypted_file = input("Enter encrypted file path: ").strip()
    
    if not key_path or not encrypted_file:
        print("Error: Key path and encrypted file path must be specified.")
        return
    
    # Try to determine original format
    encrypted_path = Path(encrypted_file)
    
    # Load metadata to find original name
    metadata = load_file_metadata()
    original_name = None
    
    if metadata:
        for meta in metadata.values():
            if f"{meta['stem']}.encrypted" == encrypted_path.name:
                original_name = meta['original_name']
                break
    
    if original_name:
        default_output = f"input/{original_name}"
        output_file = input(f"Enter path to save decrypted file [default: {default_output}]: ").strip()
        output_file = output_file if output_file else default_output
    else:
        output_file = input("Enter path to save decrypted file: ").strip()
        if not output_file:
            print("Output file path is required.")
            return
    
    key = encryptor.load_key(key_path)
    encryptor.decrypt_file(encrypted_file, output_file, key)
    
    # Verify restoration
    output_path = Path(output_file)
    if output_path.exists():
        file_size = output_path.stat().st_size
        print("File decrypted successfully!")
        print(f"Restored: {output_file} ({file_size} bytes)")
    else:
        print("File decrypted but could not verify restoration.")

def display_input_files():
    """Show files currently in input directory"""
    files = get_files_in_input_directory()
    if files:
        print("\nFiles currently in 'input' directory:")
        for i, file_path in enumerate(files, 1):
            file_size = file_path.stat().st_size
            print(f"  {i}. {file_path.name} ({file_size} bytes)")
    else:
        print("\nNo files in 'input' directory.")
    return files

def main():
    encryptor = SecureFileEncryptor()
    setup_directories()
    
    print("=" * 50)
    print("      SECURE FILE ENCRYPTION SYSTEM")
    print("=" * 50)
    
    # Show current files in input directory
    display_input_files()
    
    print("\nAvailable Operations:")
    print("1. Encrypt ALL files in 'input' directory")
    print("2. Decrypt files to 'input' directory (restore original formats)") 
    print("3. Encrypt specific file")
    print("4. Decrypt specific file")
    print("5. View files in input directory")
    
    choice = input("\nChoose option (1-5): ").strip()
    
    try:
        if choice == '1':
            # Encrypt all files in input directory
            print("\n" + "=" * 40)
            print("ENCRYPTING ALL FILES IN INPUT DIRECTORY")
            print("=" * 40)
            key = encrypt_all_files_in_input()
            if key:
                print("\n✅ Encryption complete!")
                print("📁 Encrypted files are in 'output' directory")
                print("🔑 Keep 'key.bin' and 'file_metadata.json' safe for decryption")

        elif choice == '2':
            # Decrypt all files to input directory
            print("\n" + "=" * 40)
            print("DECRYPTING FILES TO INPUT DIRECTORY")
            print("=" * 40)
            decrypt_to_input_directory()
            print("\n✅ Decryption complete!")
            print("📁 Files have been restored to 'input' directory with original formats")

        elif choice == '3':
            # Encrypt specific file
            print("\n" + "=" * 40)
            print("ENCRYPT SPECIFIC FILE")
            print("=" * 40)
            encrypt_specific_file()

        elif choice == '4':
            # Decrypt specific file
            print("\n" + "=" * 40)
            print("DECRYPT SPECIFIC FILE")
            print("=" * 40)
            decrypt_specific_file()
            
        elif choice == '5':
            # View files
            display_input_files()
            
        else:
            print("Invalid choice. Please select 1-5.")
            
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    main()