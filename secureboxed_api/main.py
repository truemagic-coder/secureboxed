import os
import click
import sqlite3
import base64
import secrets
import json
import shutil
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from solders.keypair import Keypair
from shadow_drive import ShadowDriveClient
from solana.rpc.async_api import AsyncClient

# Initialize Solana client
solana_client = AsyncClient("https://rpc.secureboxed.com")

# Database and credentials file setup
HOME_DIR = Path.home()
SECUREBOXED_DIR = HOME_DIR / '.secureboxed'
DB_FILE = SECUREBOXED_DIR / 'shadow_drive.db'
CREDS_FILE = SECUREBOXED_DIR / 'shadow_drive_creds.json'

# Ensure .secureboxed directory exists
SECUREBOXED_DIR.mkdir(exist_ok=True)

def get_db():
    conn = sqlite3.connect(str(DB_FILE))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users
                    (public_key TEXT PRIMARY KEY, encrypted_data TEXT, salt BLOB)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS files
                    (id INTEGER PRIMARY KEY, user_public_key TEXT, filename TEXT, size INTEGER, url TEXT, is_directory BOOLEAN)''')
    conn.commit()
    conn.close()

def get_encryption_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()

def save_credentials(public_key, password):
    with open(CREDS_FILE, 'w') as f:
        json.dump({'public_key': public_key, 'password': password}, f)

def load_credentials():
    if CREDS_FILE.exists():
        with open(CREDS_FILE, 'r') as f:
            return json.load(f)
    return None

def get_user_session():
    creds = load_credentials()
    if creds:
        return creds['public_key'], creds['password']
    public_key = click.prompt('Enter your public key')
    password = click.prompt('Enter your password', hide_input=True)
    return public_key, password

@click.group()
@click.pass_context
def cli(ctx):
    ctx.ensure_object(dict)
    init_db()

@cli.command()
@click.option('--public-key', prompt='Enter your public key')
@click.option('--password', prompt='Enter a password', hide_input=True, confirmation_prompt=True)
@click.option('--save', is_flag=True, help='Save credentials for future use')
def login(public_key, password, save):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE public_key = ?', (public_key,)).fetchone()

    if user is None:
        salt = secrets.token_bytes(16)  # Generate a secure random salt
        encryption_key = get_encryption_key(password, salt)
        shadow_drive_keypair = Keypair()
        encrypted_data = encrypt_data(shadow_drive_keypair.to_base58_string(), encryption_key)
        
        conn.execute('INSERT INTO users (public_key, encrypted_data, salt) VALUES (?, ?, ?)',
                     (public_key, encrypted_data, salt))
        conn.commit()
        click.echo('New user created and SHDW drive setup complete')
    else:
        click.echo('User logged in')

    conn.close()

    if save:
        save_credentials(public_key, password)
        click.echo('Credentials saved for future use')

@cli.command()
@click.argument('path')
def upload(path):
    public_key, password = get_user_session()

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE public_key = ?', (public_key,)).fetchone()

    if user is None:
        click.echo('User not found')
        return

    salt = user['salt']
    encryption_key = get_encryption_key(password, salt)
    shadow_drive_private_key = decrypt_data(user['encrypted_data'], encryption_key)
    shadow_drive_keypair = Keypair.from_base58_string(shadow_drive_private_key)
    shadow_drive_client = ShadowDriveClient(shadow_drive_keypair)

    path = Path(path)
    if path.is_file():
        upload_file(conn, public_key, shadow_drive_client, path)
    elif path.is_dir():
        upload_directory(conn, public_key, shadow_drive_client, path)
    else:
        click.echo(f"Path {path} does not exist")

    conn.close()

def upload_file(conn, public_key, shadow_drive_client, file_path):
    with open(file_path, 'rb') as f:
        contents = f.read()

    urls = shadow_drive_client.upload_files([str(file_path)])

    conn.execute('INSERT INTO files (user_public_key, filename, size, url, is_directory) VALUES (?, ?, ?, ?, ?)',
                 (public_key, str(file_path), len(contents), urls[0], False))
    conn.commit()

    click.echo(f'File {file_path} uploaded successfully')

def upload_directory(conn, public_key, shadow_drive_client, dir_path):
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            file_path = Path(root) / file
            upload_file(conn, public_key, shadow_drive_client, file_path)
    
    conn.execute('INSERT INTO files (user_public_key, filename, size, url, is_directory) VALUES (?, ?, ?, ?, ?)',
                 (public_key, str(dir_path), 0, '', True))
    conn.commit()

    click.echo(f'Directory {dir_path} uploaded successfully')

@cli.command()
@click.argument('path')
def download(path):
    public_key, password = get_user_session()

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE public_key = ?', (public_key,)).fetchone()
    file_info = conn.execute('SELECT * FROM files WHERE user_public_key = ? AND filename = ?',
                             (public_key, path)).fetchone()

    if user is None or file_info is None:
        click.echo('User or file/directory not found')
        return

    salt = user['salt']
    encryption_key = get_encryption_key(password, salt)
    shadow_drive_private_key = decrypt_data(user['encrypted_data'], encryption_key)
    shadow_drive_keypair = Keypair.from_base58_string(shadow_drive_private_key)
    shadow_drive_client = ShadowDriveClient(shadow_drive_keypair)

    if file_info['is_directory']:
        download_directory(conn, public_key, shadow_drive_client, path)
    else:
        download_file(shadow_drive_client, file_info)

    conn.close()

def download_file(shadow_drive_client, file_info):
    file_data = shadow_drive_client.get_file(file_info['url'])
    file_path = Path(file_info['filename'])
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with open(file_path, 'wb') as f:
        f.write(file_data)

    click.echo(f'File {file_path} downloaded successfully')

def download_directory(conn, public_key, shadow_drive_client, dir_path):
    files = conn.execute('SELECT * FROM files WHERE user_public_key = ? AND filename LIKE ?',
                         (public_key, f"{dir_path}%")).fetchall()

    for file in files:
        if not file['is_directory']:
            download_file(shadow_drive_client, file)

    click.echo(f'Directory {dir_path} downloaded successfully')

@cli.command()
def list_files():
    public_key, _ = get_user_session()

    conn = get_db()
    files = conn.execute('SELECT filename, size, is_directory FROM files WHERE user_public_key = ?', (public_key,)).fetchall()
    
    if not files:
        click.echo('No files found')
    else:
        for file in files:
            file_type = "Directory" if file['is_directory'] else "File"
            size = "N/A" if file['is_directory'] else f"{file['size']} bytes"
            click.echo(f"{file_type}: {file['filename']}, Size: {size}")

    conn.close()

if __name__ == '__main__':
    cli()
