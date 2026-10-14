import diagnostic_services as service_module


def setup_function():
    service_module.SERVICE_TOKEN = "test-token"


def test_latency_rejects_missing_token():
    client = service_module.app.test_client()
    response = client.get("/latency")
    assert response.status_code == 401


def test_latency_accepts_valid_token():
    client = service_module.app.test_client()
    response = client.get(
        "/latency",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    assert response.json["service"] == "latency"


def test_traceroute_accepts_valid_token():
    client = service_module.app.test_client()
    response = client.get(
        "/traceroute",
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    assert len(response.json["hops"]) == 3


def test_health_is_public():
    client = service_module.app.test_client()
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "available"


def test_invalid_token_is_rejected():
    client = service_module.app.test_client()
    response = client.get(
        "/latency",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401