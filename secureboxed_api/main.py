from fastapi import FastAPI, UploadFile, File
from fastapi.responses import Response
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

app = FastAPI()

KEY = AESGCM.generate_key(bit_length=128)

@app.post("/upload/")
async def upload_file(file: UploadFile = File(...)):
    contents = await file.read()
    aesgcm = AESGCM(KEY)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, contents, None)
    with open(f"encrypted_{file.filename}", "wb") as f:
        f.write(nonce + encrypted_data)
    return {"filename": file.filename}

@app.get("/download/{filename}")
async def download_file(filename: str):
    with open(f"encrypted_{filename}", "rb") as f:
        data = f.read()
    nonce = data[:12]
    encrypted_data = data[12:]
    aesgcm = AESGCM(KEY)
    decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
    return Response(content=decrypted_data, media_type="application/octet-stream")
