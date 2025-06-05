import redis
import json
import subprocess
import time
import os
from datetime import datetime

# === Redis Setup ===
redis_client = redis.StrictRedis(host="localhost", port=6379, decode_responses=True)
QUEUE_NAME = "queue:tmux_manager"

# === Tmux Manager Functions ===
def ensure_session(session_name):
    result = subprocess.run(["tmux", "has-session", "-t", session_name], capture_output=True)
    if result.returncode != 0:
        subprocess.run(["tmux", "new-session", "-d", "-s", session_name])
        print(f"[+] Created new tmux session: {session_name}")

def send_command_to_tmux(session, command, pane=None):
    target = f"{session}.{pane}" if pane else session
    subprocess.run(["tmux", "send-keys", "-t", target, command, "C-m"])
    # Minimal display
    print(f"[*] Sent → {command}  [{target}]")

def close_tmux_session(session_name):
    try:
        subprocess.run(["tmux", "kill-session", "-t", session_name], check=True)
        print(f"[~] Closed tmux session: {session_name}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to close tmux session {session_name}: {e}")

def capture_tmux_output(session, pane=None):
    # Support both full session or session.pane format
    target = f"{session}.{pane}" if pane else session

    result = subprocess.run(
        ["tmux", "capture-pane", "-p", "-t", target],
        capture_output=True,
        text=True
    )
    output = result.stdout.strip()

    # --- Logging Logic ---
    try:
        # Create logs directory if it doesn't exist
        os.makedirs("logs", exist_ok=True)

        # Use consistent log file per session
        log_path = os.path.join("logs", f"{target.replace('.', '_')}.log")

        with open(log_path, "a") as f:
            f.write(f"\n--- CAPTURE {datetime.utcnow().isoformat()}Z ---\n{output}\n")
    except Exception as e:
        print(f"[!] Logging error for tmux output: {e}")

    return output

# === Tmux Manager Loop ===
def run():
    print("[+] Tmux Manager is now running and waiting for tasks...")

    while True:
        task_data = redis_client.blpop(QUEUE_NAME, timeout=5)
        if not task_data:
            continue

        queue_name, task_json = task_data
        task = json.loads(task_json)
        print(f"[*] Received tmux task {task['task_id']} for command execution")

        try:
            short_task_id = task['task_id'][:8]
            session_name = f"task_{short_task_id}_{task['target'].replace('.', '_')}"

            ensure_session(session_name)

            command = task["command"]
            send_command_to_tmux(session_name, command)

            is_interactive = task.get("interactive", False)

            if not is_interactive:
                time.sleep(3)
                output = capture_tmux_output(session_name)
                task["output"] = output  # Attach output for parsing

                # === NEW: Parse structured findings from LLM ===
                from parser import parse_output_with_llm
                structured_data = parse_output_with_llm(task)
                task.update(structured_data)

                task_key = f"task:{task['task_id']}"
                existing = redis_client.get(task_key)

                if existing:
                    existing_task = json.loads(existing)
                    existing_task.update(task)
                    existing_task["status"] = "completed"
                    redis_client.set(task_key, json.dumps(existing_task))
                else:
                    task["status"] = "completed"
                    redis_client.set(task_key, json.dumps(task))

                # === Also update the task inside the task list cache ===
                service_key = task.get("service_key")
                target = task.get("target")
                if service_key and target:
                    list_key = f"tasks:{target}:{service_key}"
                    task_list_json = redis_client.get(list_key)
                    if task_list_json:
                        task_list = json.loads(task_list_json)
                        for i, t in enumerate(task_list):
                            if t.get("task_id") == task["task_id"]:
                                task_list[i].update(task)
                                break
                        redis_client.set(list_key, json.dumps(task_list))

                print(f"[+] Command executed in tmux for task {task['task_id']}")
                close_tmux_session(session_name)
                print(f"[OUTPUT for {task['task_id']}]:")
                print("\n".join(output.splitlines()[-10:]))  # Show last 10 lines

            else:
                print(f"[⚡ Interactive Task Started] {command}")
                print(f"    -> Launching interactive session handler for [{session_name}]...")

                from recon_agent import interactive_session_loop
                interactive_session_loop(session_name, task)


        except Exception as e:
            task_key = f"task:{task['task_id']}"
            existing = redis_client.get(task_key)

            if existing:
                existing_task = json.loads(existing)
                existing_task["output"] = f"[ERROR] {str(e)}"
                existing_task["status"] = "error"
                redis_client.set(task_key, json.dumps(existing_task))
            else:
                task["output"] = f"[ERROR] {str(e)}"
                task["status"] = "error"
                redis_client.set(task_key, json.dumps(task))
            print(f"[!] Error executing tmux task {task['task_id']}: {str(e)}")

if __name__ == "__main__":
    run()
