import json
import os
import redis
import subprocess
from task_router import create_task, enqueue_task
from dashboard import render_dashboard
from metrics import increment_metric

# === File Storage ===
RECON_RESULTS_DIR = "recon_results"
os.makedirs(RECON_RESULTS_DIR, exist_ok=True)

# === Redis ===
redis_client = redis.StrictRedis(host='localhost', port=6379, decode_responses=True)

def execute_recon(target_ip):
    print(f"\n[*] Starting Recon on {target_ip}...")

    recon_task = create_task(
        task_type="recon",
        target=target_ip,
        description="Initial recon and enumeration task generation",
        manual_override=False
    )

    enqueue_task(recon_task)
    print(f"[+] Recon task queued with ID: {recon_task['task_id']}")
    print("[~] Opening dashboard. You can monitor live progress and results.")
    render_dashboard(target_ip)

def clear_redis_namespace():
    for key in redis_client.scan_iter("task:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("tasks:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("recon_results:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("services:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("finalized:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("interactive:*:llm_calls"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("scratch:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("executed:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("taskgen:*:*:context"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("suggestions:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("metrics:*"):
        redis_client.delete(key)
    for key in redis_client.scan_iter("taskphase:*"):
        redis_client.delete(key)
    
    redis_client.delete("metrics")

def clear_local_logs_and_results():
    log_dirs = [
        "/home/kali/Code/logs",
        "/home/kali/Code/logs/interactive_output",
        "/home/kali/Code/logs/memory_attribution",
        "/home/kali/Code/logs/memory_merge",
        "/home/kali/Code/logs/suspicious_shares",
        "/home/kali/Code/logs/output_quality",
        "/home/kali/Code/recon_results"
    ]

    for directory in log_dirs:
        if not os.path.exists(directory):
            continue  # Skip if missing

        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    print(f"[~] Deleted file: {file_path}")
            except Exception as e:
                print(f"[!] Failed to delete {file_path}: {e}")

def kill_tmux_sessions():
    try:
        output = subprocess.check_output(["tmux", "ls"], text=True)
    except subprocess.CalledProcessError:
        print("[~] No tmux sessions to kill.")
        return

    for line in output.strip().splitlines():
        session = line.split(":")[0]
        if session.startswith("task_"):
            try:
                subprocess.run(["tmux", "kill-session", "-t", session], check=True)
                print(f"[~] Killed tmux session: {session}")
            except subprocess.CalledProcessError as e:
                print(f"[!] Failed to kill session {session}: {e}")

if __name__ == "__main__":
    clear_redis_namespace()
    clear_local_logs_and_results()
    kill_tmux_sessions()
    os.system("clear")
    print("=== Hackbot: Automated Pentesting ===")
    target_ip = input("Enter target IP or domain: ").strip()
    if target_ip:
        execute_recon(target_ip)
    else:
        print("[-] No target entered. Exiting.")
