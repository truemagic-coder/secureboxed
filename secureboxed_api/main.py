import os
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import Response
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shadow_drive import ShadowDriveClient
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from solders.keypair import Keypair

load_dotenv()

app = FastAPI()

# Initialize encryption key (you might want to use a more secure key management system)
KEY = AESGCM.generate_key(bit_length=128)

# Initialize Solana client
solana_client = AsyncClient(os.getenv("SOLANA_RPC_URL"))

# Load the private key from .env
private_key = os.getenv("SHADOW_DRIVE_PRIVATE_KEY")
keypair = Keypair.from_base58_string(private_key)

# Initialize a single ShadowDriveClient for all operations
shadow_drive_client = ShadowDriveClient(keypair)

# Dictionary to store user sessions
user_sessions = {}


class UserSession:
    def __init__(self, public_key: Pubkey):
        self.public_key = public_key


async def get_current_user(public_key: str):
    if public_key not in user_sessions:
        raise HTTPException(status_code=401, detail="User not authenticated")
    return user_sessions[public_key]


@app.post("/login")
async def login(public_key: str):
    # Create a new session for the user
    user_sessions[public_key] = UserSession(Pubkey.from_string(public_key))
    return {"message": "Logged in successfully"}


@app.post("/upload/")
async def upload_file(
    file: UploadFile = File(...), user: UserSession = Depends(get_current_user)
):
    contents = await file.read()
    aesgcm = AESGCM(KEY)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, contents, None)

    encrypted_filename = f"encrypted_{user.public_key}_{file.filename}"
    with open(encrypted_filename, "wb") as f:
        f.write(nonce + encrypted_data)

    urls = shadow_drive_client.upload_files([encrypted_filename])

    os.remove(encrypted_filename)

    return {"filename": file.filename, "url": urls[0]}


@app.get("/download/{filename}")
async def download_file(filename: str, user: UserSession = Depends(get_current_user)):
    current_files = shadow_drive_client.list_files()

    file_url = next(
        (f for f in current_files if f.endswith(f"{user.public_key}_{filename}")), None
    )
    if not file_url:
        raise HTTPException(status_code=404, detail="File not found")

    encrypted_data = shadow_drive_client.get_file(file_url)

    nonce = encrypted_data[:12]
    encrypted_content = encrypted_data[12:]
    aesgcm = AESGCM(KEY)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_content, None)

    return Response(content=decrypted_data, media_type="application/octet-stream")


@app.delete("/delete/{filename}")
async def delete_file(filename: str, user: UserSession = Depends(get_current_user)):
    current_files = shadow_drive_client.list_files()

    file_url = next(
        (f for f in current_files if f.endswith(f"{user.public_key}_{filename}")), None
    )
    if not file_url:
        raise HTTPException(status_code=404, detail="File not found")

    shadow_drive_client.delete_files([file_url])

    return {"message": f"File {filename} deleted successfully"}


@app.get("/list_files")
async def list_files(user: UserSession = Depends(get_current_user)):
    all_files = shadow_drive_client.list_files()
    user_files = [f for f in all_files if f"{user.public_key}_" in f]
    return {"files": user_files}


@app.post("/add_storage")
async def add_storage(size: int):
    shadow_drive_client.add_storage(size)
    return {"message": f"Added {size} bytes of storage"}


@app.post("/reduce_storage")
async def reduce_storage(size: int):
    shadow_drive_client.reduce_storage(size)
    return {"message": f"Reduced {size} bytes of storage"}
