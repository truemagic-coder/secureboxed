import pytest
from fastapi.testclient import TestClient
from secureboxed_api.main import app  # assuming your FastAPI app is in a file named secureboxed_api.main.py
from unittest.mock import AsyncMock, patch, MagicMock

client = TestClient(app)

@pytest.fixture
def mock_user_session():
    with patch('secureboxed_api.main.get_current_user') as mock:
        mock_session = MagicMock()
        mock_session.public_key = "mock_public_key"
        mock_session.encryption_key = b'mock_encryption_key'
        mock_session.shadow_drive_keypair = MagicMock()
        mock_session.shadow_drive_client = MagicMock()
        mock.return_value = mock_session
        yield mock_session

client = TestClient(app)

@pytest.mark.asyncio
async def test_login():
    # Mock the MongoDB find_one operation
    with patch('secureboxed_api.main.users_collection.find_one', new_callable=AsyncMock) as mock_find_one:
        # Mock the MongoDB insert_one operation
        with patch('secureboxed_api.main.users_collection.insert_one', new_callable=AsyncMock) as mock_insert_one:
            # Simulate a new user (find_one returns None)
            mock_find_one.return_value = None
            
            # Mock the AESGCM.generate_key and Keypair
            with patch('secureboxed_api.main.AESGCM.generate_key') as mock_generate_key:
                with patch('secureboxed_api.main.Keypair') as mock_keypair:
                    with patch('secureboxed_api.main.create_access_token') as mock_create_access_token:
                        # Mock the create_access_token function
                        mock_create_access_token.return_value = {"access_token": "mock_access_token", "token_type": "bearer"}

                        mock_generate_key.return_value = b'mock_encryption_key'
                        mock_keypair.return_value.to_base58_string.return_value = 'mock_private_key'
                        
                        response = client.post("/login", json={"public_key": "mock_public_key"})
                        
                        # Assert the response
                        assert response.status_code == 200
                        assert "access_token" in response.json()
                        assert "token_type" in response.json()
                        
                        # Verify that insert_one was called with the correct arguments
                        mock_insert_one.assert_called_once()
                        call_args = mock_insert_one.call_args[0][0]
                        assert call_args["public_key"] == "mock_public_key"
                        assert "encryption_key" in call_args
                        assert call_args["shadow_drive_private_key"] == "mock_private_key"

    # Test for an existing user
    with patch('secureboxed_api.main.users_collection.find_one', new_callable=AsyncMock) as mock_find_one:
        with patch('secureboxed_api.main.create_access_token') as mock_create_access_token:
            mock_create_access_token.return_value = {"access_token": "mock_access_token", "token_type": "bearer"}

            mock_find_one.return_value = {"public_key": "mock_public_key"}
            
            response = client.post("/login", json={"public_key": "mock_public_key"})
            
            assert response.status_code == 200
            assert "access_token" in response.json()
            assert "token_type" in response.json()
            
            # Verify that insert_one was not called for an existing user
            mock_insert_one.assert_not_called()

@pytest.mark.asyncio
async def test_upload_file(mock_user_session):
    mock_user_session.shadow_drive_client.upload_files.return_value = ["mock_url"]
    
    with patch('secureboxed_api.main.files_collection.insert_one') as mock_insert:
        files = {'file': ('test.txt', b'test content')}
        response = client.post("/upload", files=files)
        
        assert response.status_code == 200
        assert response.json() == {"filename": "test.txt", "url": "mock_url"}
        mock_insert.assert_called_once()

@pytest.mark.asyncio
async def test_download_file(mock_user_session):
    mock_file_info = {"url": "mock_url", "filename": "test.txt"}
    
    with patch('secureboxed_api.main.files_collection.find_one', return_value=mock_file_info):
        with patch('secureboxed_api.main.AESGCM.decrypt', return_value=b'decrypted content'):
            response = client.get("/download/test.txt")
            
            assert response.status_code == 200
            assert response.content == b'decrypted content'

@pytest.mark.asyncio
async def test_delete_file(mock_user_session):
    mock_file_info = {"url": "mock_url", "filename": "test.txt"}
    
    with patch('secureboxed_api.main.files_collection.find_one_and_delete', return_value=mock_file_info):
        response = client.delete("/delete/test.txt")
        
        assert response.status_code == 200
        assert response.json() == {"message": "File test.txt deleted successfully"}
        mock_user_session.shadow_drive_client.delete_files.assert_called_once_with(["mock_url"])

@pytest.mark.asyncio
async def test_list_files(mock_user_session):
    mock_files = [{"filename": "test1.txt", "size": 100}, {"filename": "test2.txt", "size": 200}]
    
    with patch('secureboxed_api.main.files_collection.find') as mock_find:
        mock_find.return_value.to_list.return_value = mock_files
        response = client.get("/list_files")
        
        assert response.status_code == 200
        assert response.json() == {"files": mock_files}

@pytest.mark.asyncio
async def test_add_storage(mock_user_session):
    mock_user_session.shadow_drive_client.add_storage.return_value = "Success"
    
    with patch('secureboxed_api.main.users_collection.update_one') as mock_update:
        response = client.post("/add_storage", json={"size_bytes": 1000000})
        
        assert response.status_code == 200
        assert response.json() == {
            "message": "Storage added successfully",
            "added_storage_bytes": 1000000,
            "result": "Success"
        }
        mock_update.assert_called_once()

@pytest.mark.asyncio
async def test_get_user_storage(mock_user_session):
    mock_result = [{"total_size": 1073741824}]  # 1 GB in bytes
    
    with patch('secureboxed_api.main.files_collection.aggregate') as mock_aggregate:
        mock_aggregate.return_value.to_list.return_value = mock_result
        response = client.get("/user_storage")
        
        assert response.status_code == 200
        assert response.json() == {
            "user": "mock_public_key",
            "total_storage_gb": 1.0
        }
