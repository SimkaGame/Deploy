import requests
import os

BASE_URL = "http://127.0.0.1:8000"

def test_secure_storage_flow():
    session = requests.Session()

    session.post(f"{BASE_URL}/login", data={"username": "alice"})

    valid_jpeg = b"\xff\xd8\xff\xdb" + b"0" * 100 
    files = {"file": ("my_photo.jpg", valid_jpeg, "image/jpeg")}
    upload_resp = session.post(f"{BASE_URL}/files/upload", files=files)
    assert upload_resp.status_code == 200
    file_id = upload_resp.json().get("file_id")

    idor_resp = session.get(f"{BASE_URL}/files/2/download")
    assert idor_resp.status_code in [403, 404]

    fake_jpeg = b"plain text content"
    files_fake = {"file": ("virus.jpg", fake_jpeg, "image/jpeg")}
    fake_resp = session.post(f"{BASE_URL}/files/upload", files=files_fake)
    assert fake_resp.status_code == 400

    down_resp = session.get(f"{BASE_URL}/files/{file_id}/download")
    assert down_resp.status_code == 200
    assert "attachment" in down_resp.headers.get("Content-Disposition", "")
    assert f'filename="my_photo.jpg"' in down_resp.headers.get("Content-Disposition", "")

    big_data = b"0" * (3 * 1024 * 1024)
    big_resp = session.post(f"{BASE_URL}/files/upload", files={"file": ("huge.jpg", big_data, "image/jpeg")})
    assert big_resp.status_code == 413

    print("Status: All tests passed")

if __name__ == "__main__":
    test_secure_storage_flow()