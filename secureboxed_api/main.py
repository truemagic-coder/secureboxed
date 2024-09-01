import os
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import Response
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shadow_drive import ShadowDriveClient
from solana.rpc.async_api import AsyncClient
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from motor.motor_asyncio import AsyncIOMotorClient
import jwt
from datetime import datetime, timedelta
import base64

load_dotenv()

app = FastAPI()

# Initialize Solana client
solana_client = AsyncClient(os.getenv("SOLANA_RPC_URL"))

# Initialize MongoDB client
mongo_client = AsyncIOMotorClient(os.getenv("MONGO_URI"))
db = mongo_client.shadow_drive_db
users_collection = db.users
files_collection = db.files

# JWT settings
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 30

# OAuth2 scheme for token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class UserSession:
    def __init__(
        self, public_key: Pubkey, encryption_key: bytes, shadow_drive_keypair: Keypair
    ):
        self.public_key = public_key
        self.encryption_key = encryption_key
        self.shadow_drive_keypair = shadow_drive_keypair
        self.shadow_drive_client = ShadowDriveClient(shadow_drive_keypair)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        public_key: str = payload.get("sub")
        if public_key is None:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )

    user = await users_collection.find_one({"public_key": public_key})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    encryption_key = base64.b64decode(user["encryption_key"])
    shadow_drive_keypair = Keypair.from_base58_string(user["shadow_drive_private_key"])
    return UserSession(
        Pubkey.from_string(public_key), encryption_key, shadow_drive_keypair
    )


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


@app.post("/login")
async def login(public_key: str):
    # Check if user exists in the database
    user = await users_collection.find_one({"public_key": public_key})

    if user is None:
        # Generate a new encryption key for the user
        encryption_key = AESGCM.generate_key(bit_length=128)
        # Generate a new ShadowDrive keypair for the user
        shadow_drive_keypair = Keypair()
        # Save the new user to the database
        await users_collection.insert_one(
            {
                "public_key": public_key,
                "encryption_key": base64.b64encode(encryption_key).decode(),
                "shadow_drive_private_key": shadow_drive_keypair.to_base58_string(),
            }
        )

    # Create access token
    access_token = create_access_token({"sub": public_key})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/shadow_drive_public_key")
async def get_shadow_drive_public_key(user: UserSession = Depends(get_current_user)):
    return {"shadow_drive_public_key": str(user.shadow_drive_keypair.pubkey())}


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...), user: UserSession = Depends(get_current_user)
):
    contents = await file.read()

    aesgcm = AESGCM(user.encryption_key)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, contents, None)

    encrypted_filename = f"encrypted_{user.public_key}_{file.filename}"
    with open(encrypted_filename, "wb") as f:
        f.write(nonce + encrypted_data)

    urls = user.shadow_drive_client.upload_files([encrypted_filename])

    os.remove(encrypted_filename)

    # Save file information to the database
    await files_collection.insert_one(
        {
            "user_public_key": str(user.public_key),
            "filename": file.filename,
            "size": len(contents),
            "url": urls[0],
        }
    )

    return {"filename": file.filename, "url": urls[0]}


@app.get("/download/{filename}")
async def download_file(filename: str, user: UserSession = Depends(get_current_user)):
    file_info = await files_collection.find_one(
        {"user_public_key": str(user.public_key), "filename": filename}
    )
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")

    encrypted_data = user.shadow_drive_client.get_file(file_info["url"])

    nonce = encrypted_data[:12]
    encrypted_content = encrypted_data[12:]
    aesgcm = AESGCM(user.encryption_key)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_content, None)

    return Response(content=decrypted_data, media_type="application/octet-stream")


@app.delete("/delete/{filename}")
async def delete_file(filename: str, user: UserSession = Depends(get_current_user)):
    file_info = await files_collection.find_one_and_delete(
        {"user_public_key": str(user.public_key), "filename": filename}
    )
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")

    user.shadow_drive_client.delete_files([file_info["url"]])

    return {"message": f"File {filename} deleted successfully"}


@app.get("/list_files")
async def list_files(user: UserSession = Depends(get_current_user)):
    user_files = await files_collection.find(
        {"user_public_key": str(user.public_key)}
    ).to_list(None)
    return {
        "files": [{"filename": f["filename"], "size": f["size"]} for f in user_files]
    }


@app.post("/add_storage")
async def add_storage(size_bytes: int, user: UserSession = Depends(get_current_user)):
    try:
        # Assuming the ShadowDriveClient has a method to add storage
        result = user.shadow_drive_client.add_storage(size_bytes)

        # Update the user's storage information in the database
        await users_collection.update_one(
            {"public_key": str(user.public_key)},
            {"$inc": {"total_storage": size_bytes}},
        )

        return {
            "message": "Storage added successfully",
            "added_storage_bytes": size_bytes,
            "result": result,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to add storage: {str(e)}")


@app.get("/user_storage")
async def get_user_storage(user: UserSession = Depends(get_current_user)):
    pipeline = [
        {"$match": {"user_public_key": str(user.public_key)}},
        {"$group": {"_id": None, "total_size": {"$sum": "$size"}}},
    ]
    result = await files_collection.aggregate(pipeline).to_list(None)

    if result:
        total_size_bytes = result[0]["total_size"]
        total_size_gb = total_size_bytes / (1024 * 1024 * 1024)  # Convert bytes to GB
        return {
            "user": str(user.public_key),
            "total_storage_gb": round(total_size_gb, 4),
        }
    else:
        return {
            "user": str(user.public_key),
            "total_storage_gb": 0,
        }
