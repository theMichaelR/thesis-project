# metrics.py
import redis
import json

redis_client = redis.StrictRedis(host="localhost", port=6379, decode_responses=True)

def increment_metric(key: str):
    raw = redis_client.get("metrics")
    metrics = json.loads(raw) if raw else {}
    metrics[key] = metrics.get(key, 0) + 1
    redis_client.set("metrics", json.dumps(metrics))
    print(f"[METRIC] Incremented {key} → {metrics[key]}")

def get_all_metrics():
    raw = redis_client.get("metrics")
    return json.loads(raw) if raw else {}
