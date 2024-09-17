import os
import click
import sqlite3
import base64
from pathlib import Path
from solders.keypair import Keypair
from shadow_drive import ShadowDriveClient
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Credentials file setup
HOME_DIR = Path.home()
SECUREBOXED_DIR = HOME_DIR / '.secureboxed'
DB_FILE = SECUREBOXED_DIR / 'shadow_drive_creds.db'

# Ensure .secureboxed directory exists
SECUREBOXED_DIR.mkdir(exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS credentials
    (id INTEGER PRIMARY KEY, private_key TEXT, encryption_key TEXT)
    ''')
    conn.commit()
    conn.close()

def save_credentials(private_key, encryption_key):
    init_db()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM credentials')  # Remove any existing credentials
    cursor.execute('INSERT INTO credentials (private_key, encryption_key) VALUES (?, ?)',
                   (private_key, encryption_key))
    conn.commit()
    conn.close()

def load_credentials():
    if DB_FILE.exists():
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT private_key, encryption_key FROM credentials')
        result = cursor.fetchone()
        conn.close()
        if result:
            return result
    return None, None

def get_shadow_drive_client(password):
    encrypted_private_key, encrypted_encryption_key = load_credentials()
    if encrypted_private_key is None:
        click.echo("No credentials found. Please run 'setup' command first.")
        return None
    
    f = Fernet(generate_encryption_key(password))
    
    try:
        private_key = f.decrypt(encrypted_private_key.encode()).decode()
        keypair = Keypair.from_base58_string(private_key)
        return ShadowDriveClient(keypair)
    except:
        click.echo("Invalid password or corrupted credentials.")
        return None

def gb_to_bytes(gb):
    return int(gb * 1024 * 1024 * 1024)

def bytes_to_gb(bytes):
    return round(bytes / (1024 * 1024 * 1024), 2)

def generate_encryption_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path, key):
    f = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    return encrypted_data

def decrypt_file(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data)

@click.group()
def cli():
    pass

@cli.command()
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--private-key', prompt=True, hide_input=True, help='Your existing SHDW Drive private key (leave empty to generate new)', default=None)
def setup(password, private_key):
    """Set up or update your SHDW Drive credentials"""
    if private_key is None:
        keypair = Keypair()
        private_key = keypair.to_base58_string()
        click.echo(f"Generated new keypair. Public key: {keypair.pubkey()}")
        click.echo("Make sure to fund this new wallet with SHDW tokens.")
    else:
        try:
            keypair = Keypair.from_base58_string(private_key)
        except ValueError:
            click.echo("Invalid private key. Please make sure you've entered it correctly.")
            return

    encryption_key = generate_encryption_key(password)
    
    # Encrypt the credentials before saving
    f = Fernet(generate_encryption_key(password))
    encrypted_private_key = f.encrypt(private_key.encode()).decode()
    encrypted_encryption_key = f.encrypt(encryption_key).decode()
    
    save_credentials(encrypted_private_key, encrypted_encryption_key)
    click.echo(f"Credentials saved successfully in {DB_FILE}.")
    click.echo(f"Your SHDW Drive public key: {keypair.pubkey()}")

@cli.command()
@click.argument('path')
@click.option('--password', prompt=True, hide_input=True)
@click.option('--encrypt', is_flag=True, help='Encrypt the file before uploading')
def upload(path, password, encrypt):
    client = get_shadow_drive_client(password)
    if client is None:
        return

    _, encrypted_encryption_key = load_credentials()
    if encrypted_encryption_key is None:
        click.echo("Encryption key not found. Please run 'setup' command first.")
        return

    f = Fernet(generate_encryption_key(password))
    encryption_key = f.decrypt(encrypted_encryption_key.encode())

    path = Path(path)
    if path.is_file():
        if encrypt:
            encrypted_data = encrypt_file(path, encryption_key)
            temp_file = Path(f"{path}.encrypted")
            with open(temp_file, 'wb') as f:
                f.write(encrypted_data)
            file_to_upload = temp_file
        else:
            file_to_upload = path
        
        urls = client.upload_files([str(file_to_upload)])
        
        if encrypt:
            temp_file.unlink()  # Delete the temporary encrypted file
        
        click.echo(f'File {path} uploaded successfully. URL: {urls[0]}')
    elif path.is_dir():
        for root, _, files in os.walk(path):
            for file in files:
                file_path = Path(root) / file
                if encrypt:
                    encrypted_data = encrypt_file(file_path, encryption_key)
                    temp_file = Path(f"{file_path}.encrypted")
                    with open(temp_file, 'wb') as f:
                        f.write(encrypted_data)
                    file_to_upload = temp_file
                else:
                    file_to_upload = file_path
                
                urls = client.upload_files([str(file_to_upload)])
                
                if encrypt:
                    temp_file.unlink()  # Delete the temporary encrypted file
                
                click.echo(f'File {file_path} uploaded successfully. URL: {urls[0]}')
    else:
        click.echo(f"Path {path} does not exist")

@cli.command()
@click.argument('url')
@click.argument('path')
@click.option('--password', prompt=True, hide_input=True)
@click.option('--decrypt', is_flag=True, help='Decrypt the file after downloading')
def download(url, path, password, decrypt):
    client = get_shadow_drive_client(password)
    if client is None:
        return

    _, encrypted_encryption_key = load_credentials()
    if encrypted_encryption_key is None:
        click.echo("Encryption key not found. Please run 'setup' command first.")
        return

    f = Fernet(generate_encryption_key(password))
    encryption_key = f.decrypt(encrypted_encryption_key.encode())

    file_data = client.get_file(url)
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    if decrypt:
        decrypted_data = decrypt_file(file_data, encryption_key)
        with open(file_path, 'wb') as f:
            f.write(decrypted_data)
        click.echo(f'File downloaded and decrypted successfully to {file_path}')
    else:
        with open(file_path, 'wb') as f:
            f.write(file_data)
        click.echo(f'File downloaded successfully to {file_path}')

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
def list_files(password):
    client = get_shadow_drive_client(password)
    if client is None:
        return

    files = client.list_files()
    if not files:
        click.echo('No files found')
    else:
        for file in files:
            size_gb = bytes_to_gb(file['size'])
            click.echo(f"File: {file['name']}, Size: {size_gb} GB, URL: {file['url']}")

@cli.command()
@click.argument('url')
@click.option('--password', prompt=True, hide_input=True)
def delete(url, password):
    client = get_shadow_drive_client(password)
    if client is None:
        return

    client.delete_files([url])
    click.echo(f'File with URL {url} deleted successfully')

@cli.command()
@click.option('--amount', type=float, required=True, help='Amount of storage to add in GB')
@click.option('--password', prompt=True, hide_input=True)
def add_storage(amount, password):
    client = get_shadow_drive_client(password)
    if client is None:
        return

    try:
        bytes_amount = gb_to_bytes(amount)
        client.add_storage(bytes_amount)
        click.echo(f'Successfully added {amount} GB of storage')
    except Exception as e:
        click.echo(f'Failed to add storage: {str(e)}')

@cli.command()
@click.option('--amount', type=float, required=True, help='Amount of storage to reduce in GB')
@click.option('--password', prompt=True, hide_input=True)
def reduce_storage(amount, password):
    client = get_shadow_drive_client(password)
    if client is None:
        return

    try:
        bytes_amount = gb_to_bytes(amount)
        client.reduce_storage(bytes_amount)
        click.echo(f'Successfully reduced storage by {amount} GB')
    except Exception as e:
        click.echo(f'Failed to reduce storage: {str(e)}')

if __name__ == '__main__':
    cli()
