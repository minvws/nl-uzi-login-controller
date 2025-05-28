from starlette.testclient import TestClient
from starlette import status

from app.main import run_app


def test_root_endpoint_returns_welcome_message():
    app = run_app()
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    assert response.text == "Welcome to the login controller!"


def test_root_endpoint_handles_invalid_methods():
    app = run_app()
    with TestClient(app) as client:
        response = client.post("/")
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
