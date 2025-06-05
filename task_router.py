import json
import uuid
import redis
from datetime import datetime, timezone

# === Agent Mapping ===
TASK_ROUTING_TABLE = {
    "recon": "recon_agent",
    "parser": "parser_agent",
    "vuln_analysis": "vuln_agent",
    "exploit": "exploit_agent",
    "privesc": "privesc_agent",
    "post_ex": "post_ex_agent",
    "shell": "tmux_manager",
    "manual": "human_override"
}

# === Redis Setup ===
redis_client = redis.StrictRedis(host="localhost", port=6379, decode_responses=True)
TASK_QUEUE = "task_queue"

# === Task Template ===
def create_task(task_type, target, service=None, port=None, description=None, command=None, manual_override=False, parent_task_id=None):
    task_id = str(uuid.uuid4())
    task = {
        "task_id": task_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "type": task_type,
        "target": target,
        "service": service,
        "port": port,
        "description": description,
        "command": command,
        "assigned_agent": TASK_ROUTING_TABLE.get(task_type, "unknown_agent"),
        "assigned_pane": None,
        "status": "pending",
        "output": None,
        "manual_override": manual_override
    }

    if parent_task_id:
        task["parent_task_id"] = parent_task_id

    return task

def suggest_followups(task: dict, memory: dict) -> list:
    """
    Based on memory gathered during an interactive session, suggest new tasks.
    Suggestions are pushed to a Redis queue for later pickup by generate_task_list().
    Returns the list of suggestions.
    """
    suggestions = []

    target = task.get("target")
    port = task.get("port")
    service = task.get("service", "unknown")
    queue_name = f"suggestions:{target}:{service}_{port}"

    # --- Defensive normalization for possibly malformed memory values ---
    def normalize(key):
        val = memory.get(key, [])
        if isinstance(val, str):
            return [val]
        elif isinstance(val, list):
            return [str(x) for x in val if isinstance(x, (str, int))]
        else:
            print(f"[!] Warning: Unexpected type for memory['{key}']: {type(val)}")
            return []

    known_files = normalize("known_files")
    known_shares = normalize("known_shares")
    known_flags = normalize("known_flags")
    known_users = normalize("known_users")

    # --- Suggestions from known files ---
    for f in known_files:
        if any(x in f.lower() for x in ["flag", "creds", "shadow", ".txt", "secrets"]):
            suggestion = {
                "task": f"Read contents of {f}",
                "command": f"cat {f}",
                "intent": "Review file for credentials, flags, or sensitive info",
                "subgoal": f"Inspect contents of {f}"
            }
            suggestions.append(suggestion)
            redis_client.rpush(queue_name, json.dumps(suggestion))

    # --- Suggestions from known shares ---
    for share in known_shares:
        suggestion = {
            "task": f"Explore SMB share {share}",
            "command": f"smbclient \\\\{target}\\{share} -N",
            "intent": "Browse SMB share contents",
            "subgoal": f"List and inspect files in {share}"
        }
        suggestions.append(suggestion)
        redis_client.rpush(queue_name, json.dumps(suggestion))
        print(f"[~] Suggested task for share: {share}")

    # --- Suggestions from known users ---
    for user in known_users:
        if user and isinstance(user, str) and user.lower() not in ["guest", "anonymous", "root", "kali"]:
            suggestion = {
                "task": f"Attempt user enumeration for {user}",
                "command": f"rpcclient -U {user}%'' {target}",
                "intent": "Probe RPC endpoints using known usernames",
                "subgoal": f"Check access and query info as {user}"
            }
            suggestions.append(suggestion)
            redis_client.rpush(queue_name, json.dumps(suggestion))

    return suggestions

# === Enqueue a Task ===
def enqueue_task(task):
    queue_name = f"queue:{task['assigned_agent']}"
    redis_client.rpush(queue_name, json.dumps(task))
    redis_client.set(f"task:{task['task_id']}", json.dumps(task))
    print(f"[+] Task {task['task_id']} enqueued to {queue_name} for agent {task['assigned_agent']}")

# === Task Dispatcher (optional dev tool) ===
def dispatch():
    while True:
        task_json = redis_client.lpop(TASK_QUEUE)
        if not task_json:
            break  # nothing to process now

        task = json.loads(task_json)

        if task.get("manual_override"):
            print(f"[!] Task {task['task_id']} requires human input")
            redis_client.rpush("queue:human_override", json.dumps(task))
            continue

        agent = task["assigned_agent"]
        queue_name = f"queue:{agent}"

        print(f"[*] Dispatching task {task['task_id']} to {queue_name}")
        redis_client.rpush(queue_name, json.dumps(task))

if __name__ == "__main__":
    print("[*] task_router.py is a helper module. Use hackbot.py to enqueue tasks.")
