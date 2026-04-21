# API Design (HTTP `GET /events`)

## Endpoint

- `GET /events?limit=25`
- `limit` is clamped to \([1, 100]\)

Response:

```json
{
  "items": [ { "...": "..." } ],
  "count": 25
}
```

## Implementation

The API is deployed via AWS SAM as an **HTTP API**:

- `HttpApi` in `infra/sam/template.yaml`
- `ListEventsFunction` in `pipeline/read_api/handler.py`

The function queries DynamoDB using the `timeline-received_at` GSI with:

- `timeline_pk = "GLOBAL"`
- `ScanIndexForward = false` (newest first)

## CORS

The SAM template enables permissive CORS for development. For production:

- restrict `AllowOrigins` to your frontend domain
- consider auth (Cognito / JWT) if you will expose analytics publicly

