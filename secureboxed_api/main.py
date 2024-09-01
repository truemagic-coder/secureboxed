from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import Response
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shadow_drive import ShadowDriveClient
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from solders.signature import Signature
import os
import time

app = FastAPI()

# Initialize encryption key (you might want to use a more secure key management system)
KEY = AESGCM.generate_key(bit_length=128)

# Initialize Solana client
solana_client = AsyncClient("https://api.mainnet-beta.solana.com")

# Dictionary to store user sessions
user_sessions = {}


class UserSession:
    def __init__(self, public_key: Pubkey):
        self.public_key = public_key
        self.shadow_drive_client = None
        self.account = None


async def get_current_user(public_key: str):
    if public_key not in user_sessions:
        raise HTTPException(status_code=401, detail="User not authenticated")
    return user_sessions[public_key]


@app.post("/login")
async def login(public_key: str):
    # Create a new session for the user
    user_sessions[public_key] = UserSession(Pubkey.from_string(public_key))
    return {"message": "Logged in successfully"}


@app.post("/initialize_shadow_drive")
async def initialize_shadow_drive(user: UserSession = Depends(get_current_user)):
    # Generate a message for the user to sign
    message = f"Initialize ShadowDrive for {user.public_key} at {time.time()}"
    return {"message": message}


@app.post("/verify_shadow_drive_initialization")
async def verify_shadow_drive_initialization(
    signature: str, user: UserSession = Depends(get_current_user)
):
    # Verify the signature
    try:
        Signature.from_string(signature).verify(
            user.public_key, b"Initialize ShadowDrive"
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        # Initialize ShadowDriveClient
        user.shadow_drive_client = ShadowDriveClient(user.public_key)

        # Create a storage account
        size = 2**20  # 1 MB
        user.account, tx = user.shadow_drive_client.create_account(
            "user_account", size, use_account=True
        )

        # Wait for the transaction to be confirmed
        await solana_client.is_confirmed(tx)

        return {
            "message": "ShadowDrive initialized successfully",
            "account": str(user.account),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to initialize ShadowDrive: {str(e)}"
        )


@app.post("/upload/")
async def upload_file(
    file: UploadFile = File(...), user: UserSession = Depends(get_current_user)
):
    if not user.shadow_drive_client:
        raise HTTPException(status_code=400, detail="ShadowDrive not initialized")

    contents = await file.read()
    aesgcm = AESGCM(KEY)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, contents, None)

    encrypted_filename = f"encrypted_{file.filename}"
    with open(encrypted_filename, "wb") as f:
        f.write(nonce + encrypted_data)

    urls = user.shadow_drive_client.upload_files([encrypted_filename])

    os.remove(encrypted_filename)

    return {"filename": file.filename, "url": urls[0]}


@app.get("/download/{filename}")
async def download_file(filename: str, user: UserSession = Depends(get_current_user)):
    if not user.shadow_drive_client:
        raise HTTPException(status_code=400, detail="ShadowDrive not initialized")

    current_files = user.shadow_drive_client.list_files()

    file_url = next((f for f in current_files if f.endswith(filename)), None)
    if not file_url:
        raise HTTPException(status_code=404, detail="File not found")

    encrypted_data = user.shadow_drive_client.get_file(file_url)

    nonce = encrypted_data[:12]
    encrypted_content = encrypted_data[12:]
    aesgcm = AESGCM(KEY)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_content, None)

    return Response(content=decrypted_data, media_type="application/octet-stream")


@app.delete("/delete/{filename}")
async def delete_file(filename: str, user: UserSession = Depends(get_current_user)):
    if not user.shadow_drive_client:
        raise HTTPException(status_code=400, detail="ShadowDrive not initialized")

    current_files = user.shadow_drive_client.list_files()

    file_url = next((f for f in current_files if f.endswith(filename)), None)
    if not file_url:
        raise HTTPException(status_code=404, detail="File not found")

    user.shadow_drive_client.delete_files([file_url])

    return {"message": f"File {filename} deleted successfully"}


@app.get("/list_files")
async def list_files(user: UserSession = Depends(get_current_user)):
    if not user.shadow_drive_client:
        raise HTTPException(status_code=400, detail="ShadowDrive not initialized")

    current_files = user.shadow_drive_client.list_files()
    return {"files": current_files}


@app.post("/add_storage")
async def add_storage(size: int, user: UserSession = Depends(get_current_user)):
    if not user.shadow_drive_client:
        raise HTTPException(status_code=400, detail="ShadowDrive not initialized")

    user.shadow_drive_client.add_storage(size)
    return {"message": f"Added {size} bytes of storage"}


@app.post("/reduce_storage")
async def reduce_storage(size: int, user: UserSession = Depends(get_current_user)):
    if not user.shadow_drive_client:
        raise HTTPException(status_code=400, detail="ShadowDrive not initialized")

    user.shadow_drive_client.reduce_storage(size)
    return {"message": f"Reduced {size} bytes of storage"}


@app.delete("/delete_account")
async def delete_account(user: UserSession = Depends(get_current_user)):
    if not user.shadow_drive_client or not user.account:
        raise HTTPException(
            status_code=400, detail="ShadowDrive not initialized or account not created"
        )

    user.shadow_drive_client.delete_account(user.account)
    user.account = None
    user.shadow_drive_client = None
    return {"message": "Account deleted successfully"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
