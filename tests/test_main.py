from fastapi.testclient import TestClient
from secureboxed_api.main import app

client = TestClient(app)

def test_upload_download_file():
    file_content = b"Test file content"
    with open("test_file.txt", "wb") as f:
        f.write(file_content)

    with open("test_file.txt", "rb") as f:
        response = client.post("/upload/", files={"file": ("test_file.txt", f)})
    assert response.status_code == 200
    assert response.json() == {"filename": "test_file.txt"}

    response = client.get("/download/test_file.txt")
    assert response.status_code == 200

    downloaded_content = response.content
    assert downloaded_content == file_content
