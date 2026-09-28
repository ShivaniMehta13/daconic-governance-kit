"""Small client for the Langflow monitor traces API."""
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class TraceAPIError(RuntimeError):
    """The trace endpoint returned an error or an invalid response."""


def fetch_traces(base_url, flow_id, api_key, page=1, size=5):
    """Fetch one page of Langflow monitor traces for a flow."""
    endpoint = base_url.rstrip("/") + "/api/v1/monitor/traces?" + urlencode({
        "flow_id": flow_id,
        "page": page,
        "size": size,
    })
    request = Request(endpoint, headers={"X-API-Key": api_key, "Accept": "application/json"})
    try:
        with urlopen(request) as response:
            try:
                payload = json.loads(response.read())
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise TraceAPIError("Trace API returned a non-JSON response") from error
    except HTTPError as error:
        if error.code == 401:
            raise TraceAPIError("Trace API authentication failed (401 Unauthorized)") from error
        if error.code == 403:
            raise TraceAPIError("Trace API access denied (403 Forbidden)") from error
        raise TraceAPIError(f"Trace API request failed ({error.code} {error.reason})") from error
    except URLError as error:
        raise TraceAPIError(f"Trace API connection failed: {error.reason}") from error

    if not isinstance(payload, dict) or not isinstance(payload.get("traces"), list):
        raise TraceAPIError("Trace API response must be an object containing a traces list")
    return payload["traces"]