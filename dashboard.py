import os
import time
import redis
import json
import uuid
import sys
import select
from datetime import datetime
from task_router import enqueue_task
from metrics import increment_metric
from metrics import get_all_metrics
from markdown_report import generate_markdown_report

redis_client = redis.StrictRedis(host="localhost", port=6379, decode_responses=True)

def get_session_start_time(target_ip):
    timestamps = []
    for key in redis_client.scan_iter("task:*"):
        try:
            task_data = json.loads(redis_client.get(key))
            if task_data.get("target") == target_ip:
                created_at = task_data.get("created_at")
                if created_at:
                    timestamps.append(created_at)
        except Exception:
            continue
    if timestamps:
        return min(timestamps)
    return "[unknown]"

def load_metrics():
    try:
        raw = redis_client.get("metrics")
        if raw:
            return json.loads(raw)
    except Exception as e:
        print(f"[!] Failed to load metrics: {e}")
    return {}

def non_blocking_input(prompt="", timeout=1.5):
    print(prompt, end='', flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], timeout)
    if ready:
        return sys.stdin.readline().strip()
    else:
        return None

def lookup_full_task_id(short_id):
    for key in redis_client.scan_iter("task:*"):
        if key.startswith(f"task:{short_id}"):
            return key
    return None

def check_for_pending_user_tasks(target_ip, pending_tasks):
    if not pending_tasks:
        return
    print("\n🕹️ Pending Commands")
    for task, service_key in pending_tasks:
        print("\n----------------------------------------")
        print(f"[Service: {task.get('service')} on port {task.get('port')}]")
        print(f"Task: {task['task']}")
        print(f"Suggested Command: {task['command']}")
        choice = input("Execute? [Y]es / [M]odify / [N]o: ").strip().lower()
        if choice == "y":
            task["status"] = "in_progress"
            enqueue_task(task)
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))
        elif choice == "m":
            task["command"] = input("Enter modified command: ").strip()
            task["status"] = "in_progress"
            enqueue_task(task)
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))
        else:
            task["status"] = "skipped"
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))

        key = f"tasks:{target_ip}:{service_key}"
        all_tasks = json.loads(redis_client.get(key))
        for i, t in enumerate(all_tasks):
            if t.get("task_id") == task["task_id"]:
                all_tasks[i] = task
                break
        redis_client.set(key, json.dumps(all_tasks))

def render_dashboard(target_ip):
    finalized_key = f"finalized:{target_ip}"

    if redis_client.exists(f"finalized:{target_ip}"):
        print("✅ Recon results already finalized for this target.")
        input("[Press Enter to exit dashboard]")
        return

    while True:
        os.system("clear")
        print("=== Hackbot Terminal Dashboard ===\n")
        print(f"🎯 Target IP: {target_ip}")
        print(f"🕐 Session Start: {get_session_start_time(target_ip)}\n")

        # 📊 Metrics block
        metrics = get_all_metrics()
        print("📊 LLM Metrics")
        print(f"   • Tasks Generated        : {metrics.get('total_tasks_generated', 0)}")
        print(f"   • LLM Calls Total        : {metrics.get('llm_calls_total', 0)}")
        print(f"   • Interactive Sessions   : {metrics.get('interactive_sessions_opened', 0)}")
        print(f"   • Memory Insights Added  : {metrics.get('memory_insights_added', 0)}")
        print()

        pending_tasks = []
        services_json = redis_client.get(f"services:{target_ip}")
        if not services_json:
            print("[-] No services discovered yet.")
            time.sleep(2)
            continue

        services = json.loads(services_json)
        for service_key, info in services.items():
            print(f"\n🔧 {info['service']} on port {info['port']}")

            task_list_json = redis_client.get(f"tasks:{target_ip}:{service_key}")
            if task_list_json:
                tasks = json.loads(task_list_json)
            else:
                # Fallback: search Redis directly for task IDs
                tasks = []
                for key in redis_client.scan_iter("task:*"):
                    try:
                        raw = redis_client.get(key)
                        if not raw:
                            continue
                        data = json.loads(raw)
                        if data.get("target") == target_ip and data.get("service_key") == service_key:
                            tasks.append(data)
                    except Exception:
                        continue

                if not tasks:
                    print("  No tasks yet.")
                    continue

            # Group tasks by phase
            phase_map = {}
            for task in tasks:
                phase = task.get("phase", 1)
                phase_map.setdefault(phase, []).append(task)

            for phase in sorted(phase_map.keys()):
                print(f"Phase {phase} tasks:")
                for idx, task in enumerate(phase_map[phase], 1):
                    task_id = task.get("task_id")
                    status = "pending"
                    if task_id:
                        stored_task = redis_client.get(f"task:{task_id}")
                        if stored_task:
                            status = json.loads(stored_task).get("status", "pending")

                    symbol = {"completed": "✔", "in_progress": "⏳", "error": "❌", "pending_user": "⬜"}.get(status, "⬜")
                    id_label = f"(ID: {task_id[:8]})" if task_id else "(no ID)"
                    print(f"   {symbol} {idx}. {task['task']}  {id_label}")

                    if status == "pending_user":
                        pending_tasks.append((task, service_key))

        check_for_pending_user_tasks(target_ip, pending_tasks)

        # === Finalization State Check ===
        already_finalized = redis_client.exists(finalized_key)

        # === Check for outstanding tasks across all phases ===
        all_done = True
        has_pending_user = False
        total_tasks_seen = 0

        PHASE_LIMIT = 5  # ⏲️ Align with recon_agent's max phase loop

        for service_key in services.keys():
            for phase in range(1, PHASE_LIMIT + 1):
                phase_key = f"tasks:{target_ip}:{service_key}:phase:{phase}"
                task_list_json = redis_client.get(phase_key)

                if not task_list_json:
                    all_done = False
                    continue

                tasks = json.loads(task_list_json)
                total_tasks_seen += len(tasks)

                for task in tasks:
                    task_id = task.get("task_id")
                    stored = redis_client.get(f"task:{task_id}")
                    if not stored:
                        all_done = False
                        continue

                    status = json.loads(stored).get("status", "")

                    if status == "pending_user":
                        has_pending_user = True
                    if status not in ["completed", "skipped", "error", "aborted"]:
                        all_done = False

        if total_tasks_seen == 0:
            all_done = False

        # === Finalization Prompt ===
        if all_done and not already_finalized and not has_pending_user:
            print("\n✅ All tasks completed for this target.")
            choice = input("Would you like to finalize and save recon results? (y/n): ").strip().lower()
            if choice == "y":
                from recon_agent import recon_finalize_results

                # Finalize recon results and mark in Redis
                recon_finalize_results(target_ip)
                redis_client.set(finalized_key, "true")
                print("[+] Recon results finalized.")

                # Small delay to ensure file system catches up
                time.sleep(1)

                # Attempt to generate markdown report
                report_path = f"/home/kali/Code/recon_results/{target_ip}_final.json"
                if os.path.exists(report_path):
                    print("[*] Generating Markdown report...")
                    from markdown_report import generate_markdown_report
                    generate_markdown_report(report_path)
                else:
                    print(f"[!] Expected final.json not found at: {report_path}")

                input("[Press Enter to continue]")

        # === Interaction Menu ===
        print("\n[1] View Results   [2] Exit")
        if all_done and not already_finalized and not has_pending_user:
            print("   [3] Finalize and Save Recon Results")

        user_input = non_blocking_input("> ", timeout=2)

        if user_input is not None:
            if user_input == "1":
                task_id = input("Enter task ID to view output: ").strip()
                full_key = lookup_full_task_id(task_id)
                if full_key:
                    raw = redis_client.get(full_key)
                    if raw:
                        print("\n=== Output ===")
                        print(json.loads(raw).get("output", "[No output]"))
                    else:
                        print("[!] Task not found.")
                input("\n[Press Enter to continue]")

            elif user_input == "2":
                break

            elif user_input == "3" and all_done and not already_finalized and not has_pending_user:
                from recon_agent import recon_finalize_results
                recon_finalize_results(target_ip)
                redis_client.set(finalized_key, "true")
                print("[+] Recon results finalized.")

                time.sleep(1)
                report_path = f"/home/kali/Code/recon_results/{target_ip}_final.json"
                if os.path.exists(report_path):
                    print("[*] Generating Markdown report...")
                    generate_markdown_report(report_path)
                else:
                    print(f"[!] Expected final.json not found at {report_path}")

                input("[Press Enter to continue]")


