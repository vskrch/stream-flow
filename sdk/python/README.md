# stream-flow Python SDK

```python
from stream_flow import StreamFlowClient

client = StreamFlowClient("http://127.0.0.1:8080", proxy_auth="Basic ...")
print(client.health())
print(client.store_addon_manifest("rd"))
```
