import json
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse

import pytest

from daconic_governance.trace_client import TraceAPIError, fetch_traces


class FakeResponse:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.body


def test_fetch_traces_parses_response_and_request(monkeypatch):
    traces = [{"id": "trace-1"}, {"id": "trace-2"}]
    requests = []

    def fake_urlopen(request, timeout):
        requests.append(request)
        assert timeout == 30
        return FakeResponse(json.dumps({"traces": traces, "total": 2, "pages": 1}).encode())

    monkeypatch.setattr("daconic_governance.trace_client.urlopen", fake_urlopen)

    assert fetch_traces("https://example.test/", "flow-1", "secret", page=1, size=5) == traces
    request = requests[0]
    assert request.get_method() == "GET"
    assert parse_qs(urlparse(request.full_url).query) == {"flow_id": ["flow-1"], "page": ["1"], "size": ["5"]}
    assert request.get_header("X-api-key") == "secret"
    assert request.get_header("Accept") == "application/json"


@pytest.mark.parametrize(("status", "message"), [
    (401, "authentication failed"),
    (403, "access denied"),
])
def test_fetch_traces_handles_authentication_errors(monkeypatch, status, message):
    def fake_urlopen(request, timeout):
        raise HTTPError(request.full_url, status, "denied", {}, None)

    monkeypatch.setattr("daconic_governance.trace_client.urlopen", fake_urlopen)

    with pytest.raises(TraceAPIError, match=message):
        fetch_traces("https://example.test", "flow-1", "secret")


def test_fetch_traces_handles_other_http_errors(monkeypatch):
    def fake_urlopen(request, timeout):
        raise HTTPError(request.full_url, 500, "Server Error", {}, None)

    monkeypatch.setattr("daconic_governance.trace_client.urlopen", fake_urlopen)

    with pytest.raises(TraceAPIError, match="500 Server Error"):
        fetch_traces("https://example.test", "flow-1", "secret")


@pytest.mark.parametrize("body", [
    b"not-json",
    json.dumps({"total": 1, "pages": 1}).encode(),
    json.dumps({"traces": {"id": "not-a-list"}}).encode(),
])
def test_fetch_traces_rejects_malformed_responses(monkeypatch, body):
    monkeypatch.setattr("daconic_governance.trace_client.urlopen", lambda request, timeout: FakeResponse(body))

    with pytest.raises(TraceAPIError):
        fetch_traces("https://example.test", "flow-1", "secret")