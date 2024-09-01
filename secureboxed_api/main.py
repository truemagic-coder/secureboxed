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
from enum import Enum

load_dotenv()

app = FastAPI()

# Initialize encryption key (you might want to use a more secure key management system)
KEY = AESGCM.generate_key(bit_length=128)

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

# Initialize ShadowDriveClient with the key from .env
shadow_drive_keypair = Keypair.from_base58_string(os.getenv("SHADOW_DRIVE_PRIVATE_KEY"))
shadow_drive_client = ShadowDriveClient(shadow_drive_keypair)

class UserPlan(str, Enum):
    FREE = "free"
    BASIC = "basic"
    PRO = "pro"

PLAN_STORAGE_LIMITS = {
    UserPlan.FREE: 1 * 1024 * 1024 * 1024,  # 1 GB
    UserPlan.BASIC: 10 * 1024 * 1024 * 1024,  # 10 GB
    UserPlan.PRO: 100 * 1024 * 1024 * 1024,  # 100 GB
}

class UserSession:
    def __init__(self, public_key: Pubkey, plan: UserPlan):
        self.public_key = public_key
        self.plan = plan

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        public_key: str = payload.get("sub")
        if public_key is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    user = await users_collection.find_one({"public_key": public_key})
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return UserSession(Pubkey.from_string(public_key), UserPlan(user["plan"]))

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def check_storage_limit(user: UserSession, file_size: int):
    pipeline = [
        {"$match": {"user_public_key": str(user.public_key)}},
        {"$group": {"_id": None, "total_size": {"$sum": "$size"}}}
    ]
    result = await files_collection.aggregate(pipeline).to_list(None)
    
    current_usage = result[0]["total_size"] if result else 0
    plan_limit = PLAN_STORAGE_LIMITS[user.plan]
    
    if current_usage + file_size > plan_limit:
        raise HTTPException(status_code=403, detail="Storage limit exceeded")

@app.post("/login")
async def login(public_key: str):
    # Check if user exists in the database
    user = await users_collection.find_one({"public_key": public_key})
    
    if user is None:
        # Save the new user to the database with the free plan
        await users_collection.insert_one({"public_key": public_key, "plan": UserPlan.FREE})
    
    # Create access token
    access_token = create_access_token({"sub": public_key})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/upload")
async def upload_file(file: UploadFile = File(...), user: UserSession = Depends(get_current_user)):
    contents = await file.read()
    file_size = len(contents)
    
    # Check if the upload would exceed the user's storage limit
    await check_storage_limit(user, file_size)
    
    aesgcm = AESGCM(KEY)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, contents, None)
    
    encrypted_filename = f"encrypted_{user.public_key}_{file.filename}"
    with open(encrypted_filename, "wb") as f:
        f.write(nonce + encrypted_data)
    
    urls = shadow_drive_client.upload_files([encrypted_filename])
    
    os.remove(encrypted_filename)
    
    # Save file information to the database
    await files_collection.insert_one({
        "user_public_key": str(user.public_key),
        "filename": file.filename,
        "size": file_size,
        "url": urls[0]
    })
    
    return {"filename": file.filename, "url": urls[0]}

@app.get("/download/{filename}")
async def download_file(filename: str, user: UserSession = Depends(get_current_user)):
    file_info = await files_collection.find_one({"user_public_key": str(user.public_key), "filename": filename})
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    
    encrypted_data = shadow_drive_client.get_file(file_info["url"])
    
    nonce = encrypted_data[:12]
    encrypted_content = encrypted_data[12:]
    aesgcm = AESGCM(KEY)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_content, None)
    
    return Response(content=decrypted_data, media_type="application/octet-stream")

@app.delete("/delete/{filename}")
async def delete_file(filename: str, user: UserSession = Depends(get_current_user)):
    file_info = await files_collection.find_one_and_delete({"user_public_key": str(user.public_key), "filename": filename})
    if not file_info:
        raise HTTPException(status_code=404, detail="File not found")
    
    shadow_drive_client.delete_files([file_info["url"]])
    
    return {"message": f"File {filename} deleted successfully"}

@app.get("/list_files")
async def list_files(user: UserSession = Depends(get_current_user)):
    user_files = await files_collection.find({"user_public_key": str(user.public_key)}).to_list(None)
    return {"files": [{"filename": f["filename"], "size": f["size"]} for f in user_files]}

@app.get("/user_storage")
async def get_user_storage(user: UserSession = Depends(get_current_user)):
    pipeline = [
        {"$match": {"user_public_key": str(user.public_key)}},
        {"$group": {"_id": None, "total_size": {"$sum": "$size"}}}
    ]
    result = await files_collection.aggregate(pipeline).to_list(None)
    
    if result:
        total_size_bytes = result[0]["total_size"]
        total_size_gb = total_size_bytes / (1024 * 1024 * 1024)  # Convert bytes to GB
        plan_limit_gb = PLAN_STORAGE_LIMITS[user.plan] / (1024 * 1024 * 1024)
        return {
            "user": str(user.public_key),
            "plan": user.plan,
            "total_storage_gb": round(total_size_gb, 4),
            "storage_limit_gb": round(plan_limit_gb, 4),
            "storage_used_percentage": round((total_size_gb / plan_limit_gb) * 100, 2)
        }
    else:
        plan_limit_gb = PLAN_STORAGE_LIMITS[user.plan] / (1024 * 1024 * 1024)
        return {
            "user": str(user.public_key),
            "plan": user.plan,
            "total_storage_gb": 0,
            "storage_limit_gb": round(plan_limit_gb, 4),
            "storage_used_percentage": 0
        }

@app.post("/upgrade_plan")
async def upgrade_plan(new_plan: UserPlan, user: UserSession = Depends(get_current_user)):
    if new_plan == user.plan:
        raise HTTPException(status_code=400, detail="User is already on this plan")
    
    if PLAN_STORAGE_LIMITS[new_plan] < PLAN_STORAGE_LIMITS[user.plan]:
        raise HTTPException(status_code=400, detail="Cannot downgrade to a plan with less storage")
    
    await users_collection.update_one(
        {"public_key": str(user.public_key)},
        {"$set": {"plan": new_plan}}
    )
    
    return {"message": f"Successfully upgraded to {new_plan} plan"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

