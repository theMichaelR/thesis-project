import redis
import json
import time
import subprocess
import os
import uuid
import re
from datetime import datetime
from parser import generate_command_from_task
from parser import parse_output_with_llm
from task_router import suggest_followups
from modular_prompts import autonomy_hint
from metrics import increment_metric
from openai import OpenAI

RECON_RESULTS_DIR = "recon_results"
os.makedirs(RECON_RESULTS_DIR, exist_ok=True)

# === Redis Setup ===
redis_client = redis.StrictRedis(host="localhost", port=6379, decode_responses=True)
QUEUE_NAME = "queue:recon_agent"

def get_current_phase(target_ip, service_key):
    key = f"taskphase:{target_ip}:{service_key}"
    return int(redis_client.get(key) or 1)  # Defaults to phase 1

def increment_phase(target_ip, service_key):
    key = f"taskphase:{target_ip}:{service_key}"
    current = int(redis_client.get(key) or 1)
    redis_client.set(key, current + 1)
    print(f"[~] Incremented phase for {service_key} → Phase {current + 1}")
    return current + 1

def get_task_phase(target_ip, service_key):
    return int(redis_client.get(f"taskphase:{target_ip}:{service_key}") or 1)

def increment_task_phase(target_ip, service_key):
    redis_client.incr(f"taskphase:{target_ip}:{service_key}")

# === OpenAI Setup ===
MODEL = "gpt-4o"
OPENAI_API_KEY = ("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    print("\n[Error] OpenAI API Key missing! Set the OPENAI_API_KEY environment variable.")
    exit(1)
client = OpenAI(api_key=OPENAI_API_KEY)

def generate_task_list(target_ip, service, port, phase=1):
    TOOL_CANDIDATES = [
        "smbclient", "enum4linux", "rpcclient", "nmap", "nbtscan", "nmblookup",
        "netcat", "telnet", "nbtenum", "msfconsole", "dig", "whois", "ftp", "ssh",
        "ldapsearch", "snmpwalk", "curl", "wget", "python", "bash"
    ]

    def infer_tool_from_command(cmd):
        cmd = cmd.lower()
        for tool in TOOL_CANDIDATES:
            if tool in cmd:
                return tool
        return "unknown"

    scratch_key = f"scratch:{target_ip}:{service}_{port}:phase:{phase}"
    executed_key = f"executed:{target_ip}"
    memory_key = f"taskgen:{target_ip}:{service}_{port}:context"
    all_enriched_tasks = []

    # Handle follow-up suggestions first
    suggestion_queue = f"suggestions:{target_ip}:{service}_{port}"
    while True:
        suggestion_raw = redis_client.lpop(suggestion_queue)
        if not suggestion_raw:
            break

        try:
            suggestion = json.loads(suggestion_raw)
        except Exception as e:
            print(f"[!] Failed to parse suggestion: {e}")
            continue

        command_hash = suggestion["command"].strip().lower()
        if redis_client.sismember(executed_key, command_hash):
            print(f"[~] Skipping duplicate suggested task: {suggestion['command']}")
            continue

        temp_task_id = str(uuid.uuid4())
        command = replace_placeholders(suggestion["command"], temp_task_id)

        enriched = {
            "task": suggestion["task"],
            "command": command,
            "tool": infer_tool_from_command(command),
            "intent": suggestion.get("intent", f"Follow-up task for {service}:{port}"),
            "subgoal": suggestion.get("subgoal", f"Run `{command}` as suggested"),
            "description": f"{suggestion['task']} on {target_ip}:{port} using {command}",
            "port": port,
            "service": service,
            "target": target_ip,
            "status": "pending",
            "task_id": temp_task_id,
            "phase": phase,
            "total_phases": 1,
            "allow_shell_fallback": any(x in command for x in ["ls", "cat ", "flag.txt"])
        }

        redis_client.set(f"task:{temp_task_id}", json.dumps(enriched))
        redis_client.sadd(executed_key, command_hash)
        all_enriched_tasks.append(enriched)

    if all_enriched_tasks:
        print(f"[+] Processed {len(all_enriched_tasks)} suggested task(s) before calling LLM.")
        return all_enriched_tasks

    MAX_ITERATIONS = 5
    recon_json = redis_client.get(f"recon_results:{target_ip}") or "{}"
    recon_data = json.loads(recon_json)

    for round_num in range(1, MAX_ITERATIONS + 1):
        scratch = redis_client.get(scratch_key) or ""

        print(f"[DEBUG] Triggered taskgen for {target_ip} port {port} service {service} [Phase {phase}]")
        print(f"[DEBUG] Recon: {recon_json}")
        print(f"[DEBUG] Executed: {redis_client.smembers(executed_key)}")

        refresh_interactive_memory({"target": target_ip, "service": service, "port": port})
        context_mem = get_taskgen_memory(target_ip, f"{service}_{port}")

        known_ports = ", ".join(recon_data.get("open_ports", []))
        known_services = ", ".join([s["service"] for s in recon_data.get("services", {}).values()])
        known_users = ", ".join(context_mem.get("users_found", []))
        known_shares = ", ".join(context_mem.get("known_shares", []))
        known_files = ", ".join(context_mem.get("known_files", []))

        primary_share = context_mem.get("known_shares", [None])[0]
        primary_user = context_mem.get("users_found", [None])[0]
        primary_file = context_mem.get("known_files", [None])[0]

        extra_guidance = f"""
        Additional Context:
        - If you reference a specific share, use: {primary_share or '[no known share]'}
        - If referencing a user, use: {primary_user or '[no known user]'}
        - If referencing a file, use: {primary_file or '[no known file]'}
        - Do not use placeholders like [share_name], [username], or [file_name]. Use known values instead.
        """

        prompt = f"""
        You are a cybersecurity assistant helping to enumerate a target system.

        The user has discovered the service \"{service}\" running on port {port} of {target_ip}.

        Your job is to:
        1. Suggest useful enumeration tasks for this service using Kali Linux tools.
        2. Output a structured JSON with these tasks.

        Your JSON **must** follow this structure:
        {{
        "scratchpad": "Short internal notes justifying your choices",
        "tasks": [
            {{
            "task": "Describe what to do",
            "command": "The exact command to run",
            "intent": "What the agent is trying to achieve overall",
            "subgoal": "Immediate purpose of this specific command"
            }}
        ]
        }}

        📌 Known Recon Results:
        - Open ports: {known_ports or '[unknown]'}
        - Services: {known_services or '[unknown]'}
        - Users: {known_users or '[none]'}
        - Shares: {known_shares or '[none]'}
        - Files: {known_files or '[none]'}

        🧠 Prior suggestions:
        {scratch or '[none yet]'}

        Guidelines:
        - Think in phases:
        - Phase 1: Broad discovery (e.g., list services, shares, users)
        - Phase 2+: Use earlier results to drive focused follow-ups (e.g., inspect discovered shares, probe user details, retrieve files)
        - Begin with lightweight, high-yield commands before deeper or tool-specific probes.
        - Suggest only tools installed on Kali Linux.
        - Avoid repeating commands or overlapping functionality.
        - Tailor tasks to available recon data (e.g., follow up on known users or shares).
        - If no new data is found, intelligently pivot to alternate tools or protocols.
        - You must replace placeholder variables like [share_name] or [username] with known values if available.
        - Use previously discovered values from recon memory. For example:
        - known_shares: {known_shares}
        - known_users: {known_users}

        Do **not** include extra text or markdown. Your output must be a pure JSON object.

        {extra_guidance}
        """

        try:
            increment_metric("llm_calls_total")
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity enumeration assistant."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1000
            )
            raw_content = response.choices[0].message.content.strip()

            if raw_content.startswith("```"):
                raw_content = raw_content.lstrip("`").lstrip("json").strip()
                if raw_content.endswith("```"):
                    raw_content = raw_content[:-3].strip()

            parsed = json.loads(raw_content)
            scratch_text = parsed.get("scratchpad", "")
            redis_client.set(scratch_key, scratch_text.strip())

            new_tasks = parsed.get("tasks", [])
            for i, task in enumerate(new_tasks):
                command = task["command"].strip()
                command = replace_placeholders(command, task_id := str(uuid.uuid4()))
                command_hash = command.lower()
                if redis_client.sismember(executed_key, command_hash):
                    continue

                enriched = {
                    "task": task["task"],
                    "command": command,
                    "tool": infer_tool_from_command(command),
                    "intent": task.get("intent", f"Enumerate {service} on port {port} at {target_ip}"),
                    "subgoal": task.get("subgoal", f"Run `{command}` to {task['task'].lower()}"),
                    "description": f"{task['task']} on {target_ip}:{port} using {command}",
                    "port": port,
                    "service": service,
                    "target": target_ip,
                    "status": "pending",
                    "task_id": task_id,
                    "phase": phase,
                    "total_phases": len(new_tasks),
                    "allow_shell_fallback": any(x in command for x in ["ls", "cat ", "flag.txt"])
                }

                redis_client.set(f"task:{task_id}", json.dumps(enriched))
                redis_client.sadd(executed_key, command_hash)
                all_enriched_tasks.append(enriched)
                increment_metric("total_tasks_generated")

            from recon_agent import extract_reasoning_block, update_taskgen_memory
            reasoning = extract_reasoning_block(raw_content)
            update_taskgen_memory(target_ip, f"{service}_{port}", {
                "last_reasoning": reasoning,
                "last_tasks": [t["command"] for t in new_tasks],
                "discovered_tools": [infer_tool_from_command(t["command"]) for t in new_tasks]
            })

            if all_enriched_tasks:
                break

        except Exception as e:
            print(f"[Error] LLM Task List Generation Failed (Round {round_num}): {str(e)}")

    return all_enriched_tasks

# TASK GENERATION HELPERS
def extract_reasoning_block(response_text):
    try:
        pattern = r"🧠 Reasoning:\s*(.+?)(?:\n\{|\Z)"
        match = re.search(pattern, response_text, re.DOTALL)

        if match:
            reasoning = match.group(1).strip()
            if not isinstance(reasoning, str):
                print(f"[!] Unexpected type for reasoning: {type(reasoning)} — {repr(reasoning)}")
                return ""
            return reasoning
        else:
            print("[!] Failed to extract reasoning from LLM response.")
            return ""
    except Exception as e:
        print(f"[!] Exception in extract_reasoning_block: {e}")
        return ""

def get_taskgen_memory(target_ip, service_key):
    key = f"taskgen:{target_ip}:{service_key}:context"
    raw = redis_client.get(key)
    if not raw:
        return {
            "intent": "",
            "known_ports": [],
            "known_services": [],
            "discovered_tools": [],
            "discovered_shares": [],
            "host_os_guess": "",
            "last_reasoning": "",
            "last_tasks": []
        }
    return json.loads(raw)

def update_taskgen_memory(target_ip, service_key, updates):
    key = f"taskgen:{target_ip}:{service_key}:context"
    memory = get_taskgen_memory(target_ip, service_key)

    for k, v in updates.items():
        if isinstance(v, list) and isinstance(memory.get(k), list):
            memory[k] = list(set(memory[k] + v))
        else:
            memory[k] = v

    redis_client.set(key, json.dumps(memory, indent=2))

def run_command(command):
    print(f"[+] Executing: {command}")
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output_lines = []
    try:
        for line in process.stdout:
            print(line.strip())
            output_lines.append(line.strip())
    except KeyboardInterrupt:
        process.terminate()
        print("[!] Process interrupted.")
    process.wait()
    return "\n".join(output_lines)

def enumerate_services(target_ip):
    from task_router import enqueue_task  # ✅ Required for task dispatch

    services_json = redis_client.get(f"services:{target_ip}")
    if not services_json:
        print(f"[-] No services found for {target_ip}. Recon stopping.")
        return

    services = json.loads(services_json)
    service_keys = list(services.keys())
    PHASE_LIMIT = 5
    status_ok = {"completed", "skipped", "aborted", "error"}

    for phase in range(1, PHASE_LIMIT + 1):
        print(f"\n==== Starting Phase {phase} Across All Services ====\n")

        for service_key in service_keys:
            service_info = services[service_key]
            service_name = service_info["service"]
            port = service_info["port"]

            print(f"[+] Phase {phase} → {service_key}")
            print(f"[+] Enumerating {service_name} on port {port}...")

            task_list = generate_task_list(target_ip, service_name, port, phase=phase)

            if not task_list:
                print(f"[~] No tasks for {service_name} on port {port} (Phase {phase}).")
                continue

            enriched_tasks = []
            for task in task_list:
                task.update({
                    "service_key": service_key,
                    "type": "shell",
                    "target": target_ip,
                    "service": service_name,
                    "port": port,
                    "description": task["task"],
                    "assigned_agent": "tmux_manager",
                    "assigned_pane": None,
                    "manual_override": False,
                    "interactive": any(tool in task["tool"].lower() for tool in [
                        "smbclient", "ftp", "mysql", "telnet", "ssh", "psql", "rpcclient"
                    ])
                })

                if task["interactive"]:
                    from recon_agent import init_interactive_memory
                    init_interactive_memory(task)

                redis_client.set(f"task:{task['task_id']}", json.dumps(task))
                enqueue_task(task)
                enriched_tasks.append(task)

            phase_key = f"tasks:{target_ip}:{service_key}:phase:{phase}"
            redis_client.set(phase_key, json.dumps(enriched_tasks))
            print(f"[+] Saved {len(enriched_tasks)} tasks for Phase {phase} → {service_key}")
            redis_client.set(f"phase_completed:{target_ip}:{service_key}:{phase}", "true")

        print(f"[*] Waiting for Phase {phase} tasks to complete across all services...")

        print(f"[*] Monitoring Phase {phase} tasks for completion...")

        while True:
            all_done = True
            for service_key in service_keys:
                phase_key = f"tasks:{target_ip}:{service_key}:phase:{phase}"
                task_list_fetched = json.loads(redis_client.get(phase_key) or "[]")
                statuses = []

                for task in task_list_fetched:
                    task_id = task.get("task_id")
                    if not task_id:
                        continue

                    stored = redis_client.get(f"task:{task_id}")
                    if not stored:
                        statuses.append("missing")
                        continue

                    status = json.loads(stored).get("status", "pending")
                    statuses.append(status)

                if not statuses:
                    print(f"[!] No statuses found for {service_key} Phase {phase}")
                    all_done = False
                    break

                if not all(s in status_ok for s in statuses):
                    all_done = False
                    break

            if all_done:
                print(f"[✓] All Phase {phase} tasks completed successfully.")
                break

            time.sleep(2)

        else:
            # Final status check before halting
            all_done = True
            for service_key in service_keys:
                phase_key = f"tasks:{target_ip}:{service_key}:phase:{phase}"
                task_list_fetched = json.loads(redis_client.get(phase_key) or "[]")
                statuses = []

                for task in task_list_fetched:
                    task_id = task.get("task_id")
                    if not task_id:
                        continue

                    stored = redis_client.get(f"task:{task_id}")
                    if not stored:
                        statuses.append("missing")
                        continue

                    status = json.loads(stored).get("status", "pending")
                    statuses.append(status)

                if not all(s in status_ok for s in statuses):
                    all_done = False
                    break

        if all_done:
            print(f"[✓] All Phase {phase} tasks completed just in time.")
            continue  # ⬅️ this lets Phase 2 begin

        # 💤 Final short delay before halting to catch any straggler completions
        print(f"[~] Timeout waiting for Phase {phase} to complete. Pausing for final check...")
        time.sleep(5)

        # 🔁 One last re-check of statuses
        final_all_done = True
        for service_key in service_keys:
            phase_key = f"tasks:{target_ip}:{service_key}:phase:{phase}"
            task_list_fetched = json.loads(redis_client.get(phase_key) or "[]")
            statuses = []

            for task in task_list_fetched:
                task_id = task.get("task_id")
                if not task_id:
                    continue

                stored = redis_client.get(f"task:{task_id}")
                if not stored:
                    statuses.append("missing")
                    continue

                status = json.loads(stored).get("status", "pending")
                statuses.append(status)

            if not all(s in status_ok for s in statuses):
                final_all_done = False
                break

        if final_all_done:
            print(f"[✓] Final retry succeeded — proceeding to Phase {phase + 1}.")
            continue  # Let next phase begin
        
        # 💤 Final short delay before halting to catch any straggler completions
        print(f"[~] Timeout waiting for Phase {phase} to complete. Pausing for final check...")
        time.sleep(5)

        # 🔁 One last re-check of statuses
        final_all_done = True
        for service_key in service_keys:
            phase_key = f"tasks:{target_ip}:{service_key}:phase:{phase}"
            task_list_fetched = json.loads(redis_client.get(phase_key) or "[]")
            statuses = []

            for task in task_list_fetched:
                task_id = task.get("task_id")
                if not task_id:
                    continue

                stored = redis_client.get(f"task:{task_id}")
                if not stored:
                    statuses.append("missing")
                    continue

                status = json.loads(stored).get("status", "pending")
                statuses.append(status)

            if not all(s in status_ok for s in statuses):
                final_all_done = False
                break

        if final_all_done:
            print(f"[✓] Final retry succeeded — proceeding to Phase {phase + 1}.")
            continue  # Let next phase begin
        else:
            print(f"[!] Final retry failed — halting at Phase {phase}.")
            break


def run_recon(target_ip):
    print(f"[+] Starting Recon on {target_ip}")

    print("[*] Stage 1: Running Initial Nmap Scan...")
    nmap_initial_cmd = f"nmap -Pn -T5 --top-ports 1000 --stats-every 30s {target_ip}"
    nmap_initial_result = run_command(nmap_initial_cmd)

    open_ports = []
    for line in nmap_initial_result.splitlines():
        if "/tcp" in line and "open" in line:
            open_ports.append(line.split("/")[0])

    recon_data = {
        "target": target_ip,
        "open_ports": open_ports,
        "services": {},
        "tasks_completed": []
    }

    if open_ports:
        open_ports_str = ",".join(open_ports)
        print(f"[*] Stage 2: Running Follow-up Nmap Scan on Ports {open_ports_str}...")
        nmap_service_cmd = f"sudo nmap -Pn -sVC -p {open_ports_str} -T4 {target_ip}"
        nmap_service_result = run_command(nmap_service_cmd)

        discovered_services = {}
        for line in nmap_service_result.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split("/")[0]
                    service = parts[2]
                    discovered_services[f"{service}_{port}"] = {
                        "port": port,
                        "service": service,
                        "enumeration_tasks": []
                    }
        recon_data["services"] = discovered_services
        redis_client.set(f"services:{target_ip}", json.dumps(recon_data["services"]))

        # ✅ Save base recon file (you forgot this!)
        file_path = f"{RECON_RESULTS_DIR}/{target_ip}.json"
        with open(file_path, "w") as f:
            json.dump(recon_data, f, indent=4)
        print(f"[+] Base recon file saved to {file_path}")

        print("[*] Stage 3: Beginning Service Enumeration...")
        enumerate_services(target_ip)

    else:
        print(f"[!] No open ports found on {target_ip}. Skipping service enumeration.")
        redis_client.set(f"services:{target_ip}", json.dumps({}))  # Ensure key exists
        file_path = f"{RECON_RESULTS_DIR}/{target_ip}.json"
        with open(file_path, "w") as f:
            json.dump(recon_data, f, indent=4)
        return recon_data

def recon_finalize_results(target_ip):
    base_path = f"{RECON_RESULTS_DIR}/{target_ip}.json"
    if not os.path.exists(base_path):
        print(f"[!] Base recon file not found: {base_path}")
        print("[HINT] Did you delete the recon_results folder? You must run the recon agent first.")
        return

    print(f"[+] Finalizing recon results for {target_ip}...")

    with open(base_path, "r") as f:
        recon_data = json.load(f)

    services = recon_data.get("services", {})
    all_service_keys = list(services.keys())

    for service_key in all_service_keys:
        enriched_tasks = []
        phase = 1

        while True:
            task_list_key = f"tasks:{target_ip}:{service_key}:phase:{phase}"
            task_list_json = redis_client.get(task_list_key)

            if not task_list_json:
                # If no more phases found, stop here
                if phase == 1:
                    print(f"[!] No task list in Redis for {service_key}")
                break

            task_list = json.loads(task_list_json)

            for task in task_list:
                task_id = task.get("task_id")
                if not task_id:
                    continue

                task_redis_key = f"task:{task_id}"
                task_data_json = redis_client.get(task_redis_key)

                if not task_data_json:
                    print(f"[!] Missing Redis entry for task {task_id}")
                    continue

                task_data = json.loads(task_data_json)
                status = task_data.get("status", "")
                if status == "aborted":
                    status += " (API limit)"

                enriched_tasks.append({
                    "task_id": task_id,
                    "description": task_data.get("description", ""),
                    "command": task_data.get("command", ""),
                    "tool": task_data.get("tool", ""),
                    "status": status,
                    "interactive": task_data.get("interactive", False),
                    "output": task_data.get("output", "[NO OUTPUT FOUND]")
                })

            phase += 1

        # Update service with enriched tasks
        services[service_key]["enumeration_tasks"] = enriched_tasks

        # === Phase Completion Check ===
        acceptable = {"completed", "skipped", "error", "aborted"}
        all_done = all(task["status"] in acceptable for task in enriched_tasks)

        if all_done:
            phase_key = f"taskphase:{target_ip}:{service_key}"
            current_phase = int(redis_client.get(phase_key) or 1)
            redis_client.set(phase_key, current_phase + 1)
            print(f"[+] All tasks complete for {service_key}. Phase incremented to {current_phase + 1}")
        else:
            print(f"[~] Not all tasks completed for {service_key}. Holding at current phase.")

    # Save final output file
    final_path = f"{RECON_RESULTS_DIR}/{target_ip}_final.json"

    try:
        with open(final_path, "w") as f:
            json.dump(recon_data, f, indent=4)
        print(f"[✓] Final recon data written to {final_path}")
    except Exception as e:
        print(f"[!] Failed to write final recon data: {e}")

# TMUX
def close_tmux_session(session_name):
    try:
        subprocess.run(["tmux", "kill-session", "-t", session_name], check=True)
        print(f"[~] Closed interactive tmux session: {session_name}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to close tmux session {session_name}: {e}")

def capture_tmux_output(session, pane=None):
    target = f"{session}.{pane}" if pane else session
    result = subprocess.run(["tmux", "capture-pane", "-p", "-t", target], capture_output=True, text=True)
    return result.stdout.strip()

def send_command_to_tmux(session, command, pane=None):
    target = f"{session}.{pane}" if pane else session
    subprocess.run(["tmux", "send-keys", "-t", target, command, "C-m"])
    print(f"[*] Sent command to tmux [{target}]: {command}")

# INTERACTIVE SESSION

def extract_reasoning_from_response(response_text):
    """
    Extracts the reasoning block from an LLM response.
    Handles multiline content and avoids markdown artifacts.

    Args:
        response_text (str): Full LLM response text.

    Returns:
        str: The extracted reasoning text, or empty string if not found.
    """
    match = re.search(r"🧠\s*Reasoning:\s*(.+?)(?:\n\s*💻\s*Command:|\Z)", response_text, re.IGNORECASE | re.DOTALL)
    
    if not match:
        print("[!] Failed to extract reasoning.")
        return ""
    
    reasoning = match.group(1).strip()

    # 🧹 Cleanup pass: remove markdown artifacts or language tags
    reasoning = reasoning.replace("```", "")
    reasoning = reasoning.replace("plaintext", "")
    reasoning = reasoning.strip("`").strip()

    return reasoning

def interactive_session_loop(session_name, task):
    print(f"[+] Starting Interactive Session Loop for {task['task_id']}...")
    increment_metric("interactive_sessions_opened")

    session_history = []
    redis_client.set(f"interactive:{task['task_id']}:history", json.dumps(session_history))

    tool = task.get("tool", "an unknown tool").lower()
    goal = task.get("goal", "discover useful information such as flags, credentials, or configuration weaknesses")
    phase_max = task.get("llm_phase_limit", 5)
    shell_allowed = task.get("allow_shell_fallback", False)

    LLM_CALL_LIMIT = 10
    loop_count = 0

    llm_calls_key = f"interactive:{task['task_id']}:llm_calls"
    llm_call_count = int(redis_client.get(llm_calls_key) or 0)

    post_session_merge = {}

    while True:
        output = capture_tmux_output(session_name)

        if not output.strip():
            print(f"[~] Empty? {repr(output)}")
            time.sleep(2)
            continue

        print(f"[+] Captured output for session: {session_name} (length: {len(output)} chars)")

        # ✅ Log full tmux output snapshot for debugging
        log_dir = "logs/interactive_output"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{task['task_id']}_tmux_output.log")
        with open(log_path, "a") as f:
            f.write(f"\n--- OUTPUT @ {datetime.utcnow().isoformat()}Z ---\n{output}\n")

        # Update the session history first
        if session_history and session_history[-1]["output"] == "":
            session_history[-1]["output"] = output
        else:
            session_history.append({"command": "[session_start]", "output": output})

        redis_client.set(f"interactive:{task['task_id']}:history", json.dumps(session_history))

        # ✅ Assign last LLM-issued command before referencing it
        command = session_history[-1]["command"] if session_history else ""

        # ✅ FIX: Parse output before refreshing and building prompt
        output_lines = [line.strip() for line in output.strip().splitlines()]
        if len(output_lines) < 2:
            print("[!] Very short or empty output — recording as possible failure.")
            update_interactive_memory(task["task_id"], {
                "errors": ["Empty or trivial output — tool may have failed silently"],
                "notes": ["No useful lines returned from tool execution. This may indicate misconfiguration, missing target info, or silent failure."],
                "output_summary": "Empty or unhelpful output",
                "output_quality": "poor"
            })
        else:
            parse_output_and_update_memory(output, task, use_llm=True)

        refresh_interactive_memory(task)
        memory = get_interactive_memory(task["task_id"])

        # Now run shell prompt detection with up-to-date memory
        last_line = output.strip().splitlines()[-1] if output.strip() else "[empty]"
        print(f"[~] Last line of output: {last_line}")

        if looks_like_shell_prompt(output) and not shell_allowed:
            print("[+] Detected return to shell. Exiting interactive session.")
            
            # Small delay to let any final tool output settle
            time.sleep(2)
            final_output = capture_tmux_output(session_name)
            
            task["status"] = "completed"
            task["output"] = final_output
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))
            break

        if (not shell_allowed and re.search(r"\$|#|>>>|\bexit\b", last_line)) or "command not found" in output.lower():
            print("[+] Tool likely exited or returned to shell. Ending interactive session.")
            print(f"[~] Shell fallback triggered on line: {last_line}")
            task["status"] = "completed"
            task["output"] = output
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))
            break


        cred_lines = []
        for cred in memory.get("credentials_found", []):
            if isinstance(cred, dict):
                user = cred.get("username", "?")
                pw = cred.get("password", "?")
                cred_lines.append(f"{user} / {pw}")
            elif isinstance(cred, str):
                cred_lines.append(cred)
            else:
                cred_lines.append(repr(cred))

        session_context = "\n".join(
            [f"Command: {ensure_str(entry['command'])}\nOutput:\n{ensure_str(entry['output'])}\n" for entry in session_history]
        )

        hint_block = []
        last_output = session_history[-1]["output"].lower()
        if any(e in last_output for e in ["access denied", "no such file", "nt_status"]):
            hint_block.append("The last output may contain an error or failed command.")

        # Before constructing memory_block, explicitly print types to debug
        assert isinstance(memory.get("intent", ""), (str, list, type(None)))
        assert isinstance(memory.get("subgoal", ""), (str, list, type(None)))
        assert isinstance(memory.get("known_files", []), list)
        assert isinstance(memory.get("known_shares", []), list)
        assert isinstance(memory.get("credentials_found", []), list)
        assert isinstance(memory.get("errors", []), list)

        try:
            memory_block = f"""
            🧠 MEMORY:
            - Intent: {ensure_str(memory.get("intent", "[not set]"))}
            - Subgoal: {ensure_str(memory.get("subgoal", "[not set]"))}
            - Known files: {safe_join(memory.get("known_files", []))}
            - Known shares: {safe_join(memory.get("known_shares", []))}
            - Credentials found: {safe_join(memory.get("credentials_found", []))}
            - Errors so far: {safe_join(memory.get("errors", []))}
            """.strip()
        except Exception as e:
            print(f"[!] Error constructing memory block: {e}")
            memory_block = "[!] Memory block construction failed."


        # Always initialize autonomy_hint safely before use
        autonomy_hint = memory.get("autonomy_hint", [])
        if isinstance(autonomy_hint, str):
            autonomy_hint = [autonomy_hint]

        # Defensive stringify
        try:
            joined_hint = "\n".join(str(x) for x in autonomy_hint)
        except Exception as e:
            print(f"[!] Failed to join autonomy_hint: {autonomy_hint} — {e}")
            joined_hint = "[autonomy_hint join error]"

        # Inject autonomy guidance only if discoveries exist
        discovery_keys = ["known_shares", "known_files", "known_users", "known_flags", "endpoints_found"]
        if any(memory.get(k) for k in discovery_keys):
            print("[~] Injecting autonomy_hint for follow-up interaction guidance")
            print(f"[DEBUG] autonomy_hint: {type(autonomy_hint)} -> {repr(autonomy_hint)}")
            memory_block += f"\n\n{joined_hint}"

        try:
            prompt = f"""
    You are assisting with an interactive enumeration task against {task['target']}.

    ⚠️ CONTEXT:
    - You are currently interacting with: **{tool}**
    - You are in phase {llm_call_count + 1} of {phase_max}.
    - This interface accepts **only valid commands for that tool**. Do not use unrelated commands or tools.
    - If you see a password prompt, try known credentials, a blank password, or a commonly accepted guest/anonymous access format if appropriate for the tool.    
    - You may use basic commands like `ls`, `cd`, `cat` if supported by this tool.
    - If there are multiple directories remember to check them all.
    - If unsure, you may use `help`, `exit`, or `<WAIT>` to pause.

    🎯 GOAL:
    - {goal}

    {memory_block}

    📜 SESSION HISTORY:
    {session_context}

    💡 HINT:
    {safe_join(hint_block, fallback="")}

    🧠 FORMAT REQUIREMENTS (IMPORTANT):
    You must respond using the following format:

    🧠 Reasoning:
    [Summarize what the last command revealed. Then clearly state your short-term goal. Finally, explain your *next step* — what command you will run, why you chose it, and what you expect it to reveal.]

    💻 Command:
    [The raw command to enter next.]

    ❌ If you want to exit this tool to switch to a normal shell (e.g., to use commands like `cat`, `grep`, or `bash`), you MUST exit by issuing the `exit` command now. A new session will be launched with shell access.
    ❌ Do not return invalid commands. Do not use markdown. Only valid input.
    """.strip()
        except Exception as e:
            print("THE ISSUE IS IN THE PROMPT!!!")

        os.makedirs("logs", exist_ok=True)
        with open(f"logs/{task['task_id']}_prompt.log", "a") as f:
            f.write(f"\n--- PROMPT @ {datetime.utcnow().isoformat()}Z ---\n{prompt}\n")

        try:
            response = client.chat.completions.create(
                model=MODEL,
                messages=[
                    {"role": "system", "content": "You are a penetration tester issuing commands within one tool at a time. Stay within scope."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=250
            )

            raw_response = response.choices[0].message.content.strip()
            reasoning = extract_reasoning_from_response(raw_response)
            command = extract_command_from_response(raw_response)

            print("[DEBUG] Command from LLM:", command)

        except Exception as e:
            print("[🔥] LLM or command parsing failed:", e)
            task["status"] = "error"
            task["output"] = f"LLM interaction failed: {e}"
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))
            return

        # 🔧 Fix 2: Replace placeholders just before execution
        placeholder_tokens = [
            "[share_name]", "[username]", "[file_name]",
            "<share_name>", "<username>", "<file_name>", "<target_IP>"
        ]

        if any(ph in command for ph in placeholder_tokens):
            print(f"[!] Placeholder detected in command: {command}")
            command = replace_placeholders(command, task["task_id"])
            print(f"[+] Final command after replacement: {command}")

        with open(f"logs/{task['task_id']}_reasoning.log", "a") as f:
            f.write(f"\n--- REASONING @ {datetime.utcnow().isoformat()}Z ---\n{reasoning}\n")

        update_interactive_memory(task["task_id"], {
            "last_command": command,
            "last_reasoning": reasoning,
            "output_summary": "Non-empty output parsed successfully",
            "output_quality": "normal"
        })

        llm_call_count += 1
        redis_client.set(llm_calls_key, llm_call_count)

        if llm_call_count >= LLM_CALL_LIMIT:
            print(f"[!] LLM call count exceeded {LLM_CALL_LIMIT}. Aborting session.")
            task["status"] = "aborted"
            task["output"] = capture_tmux_output(session_name)
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))
            break


        if command.lower() == "exit":
            print("[+] LLM suggested exit.")
            time.sleep(5)
            final_output = capture_tmux_output(session_name)
            task["status"] = "completed"
            task["output"] = final_output  # ✅ use updated value instead of session_context
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))
            print(f"[✓] Task {task['task_id']} marked as completed in Redis.")
            break
        elif command.lower() in ("<wait>", "wait"):
            print("[~] LLM requested delay.")
            time.sleep(5)
            continue
        elif command.lower() == "<empty>":
            send_command_to_tmux(session_name, "")
            session_history.append({"command": "<empty>", "output": ""})
            time.sleep(5)
            continue

        # ✅ Replace placeholders just before execution
        placeholder_tokens = [
            "[share_name]", "[username]", "[file_name]",
            "<share_name>", "<username>", "<file_name>",
            "<IP_ADDRESS>", "<target_IP>"
        ]
        if any(ph in command for ph in placeholder_tokens):
            print(f"[!] Placeholder detected in command: {command}")
            command = replace_placeholders(command, task["task_id"])
            print(f"[+] Final command after replacement: {command}")

        print(f"[*] Sending: {command}")
        send_command_to_tmux(session_name, command)
        session_history.append({"command": command, "output": ""})
        # Detect repeated identical commands
        if len(session_history) >= 4:
            recent_commands = [entry["command"] for entry in session_history[-4:]]
            if all(cmd == recent_commands[0] and cmd not in ("", "[session_start]") for cmd in recent_commands):
                print(f"[!] Detected repeated command: {repr(recent_commands[0])} — Aborting.")
                task["status"] = "aborted"
                task["output"] = session_context
                redis_client.set(f"task:{task['task_id']}", json.dumps(task))
                break

        time.sleep(10)
        loop_count += 1

        if loop_count >= 15:
            print(f"[!] Loop count exceeded 30 iterations. Aborting to avoid runaway behavior.")
            task["status"] = "aborted"
            task["output"] = session_context
            redis_client.set(f"task:{task['task_id']}", json.dumps(task))
            break

    # Defensive catch — if status wasn't explicitly set
    if "status" not in task or task["status"] not in {"completed", "aborted", "skipped", "error"}:
        print("[~] Finalizing task with fallback status = aborted")
        task["status"] = "aborted"
        task["output"] = capture_tmux_output(session_name)
        redis_client.set(f"task:{task['task_id']}", json.dumps(task))

    # ✅ FINALIZE INTERACTIVE SESSION
    final_mem = get_interactive_memory(task["task_id"])

    for key, val in final_mem.items():
        if key.endswith("_found"):
            base = key[:-6]
            target_key = f"known_{base}"
            
            # Normalize to flat list of strings
            if isinstance(val, list):
                normalized = [str(v) for v in val]
            elif isinstance(val, str):
                normalized = [val]
            else:
                normalized = [str(val)]
            
            post_session_merge[target_key] = normalized
            print(f"[~] Normalized memory merge value for {target_key}: {normalized}")

    if post_session_merge:
        update_interactive_memory(task["task_id"], post_session_merge)

        # Attribution Logging
        log_dir = "logs/memory_merge"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{task['task_id']}_postmerge.log")
        with open(log_path, "a") as f:
            f.write(f"\n--- POST SESSION MERGE @ {datetime.utcnow().isoformat()}Z ---\n")
            for k, v in post_session_merge.items():
                f.write(f"Merged into '{k}': {v}\n")

        print(f"[+] Post-session memory merged: {list(post_session_merge.keys())}")

    # ✅ Suggest follow-up tasks based on memory
    followups = suggest_followups(task, final_mem)
    if followups:
        queue_name = f"suggestions:{task['target']}:{task['service']}_{task['port']}"
        for suggestion in followups:
            redis_client.rpush(queue_name, json.dumps(suggestion))
        print(f"[+] Queued {len(followups)} follow-up task(s) to {queue_name}")

    print(f"[+] Interactive session {task['task_id']} finalized.")
    # Kill the tmux session for this interactive task
    close_tmux_session(session_name)
    # Then update the task status
    task_key = f"task:{task['task_id']}"
    stored = redis_client.get(task_key)
    if stored:
        updated = json.loads(stored)
        updated["status"] = "completed"
        redis_client.set(task_key, json.dumps(updated))
        print(f"[+] Marked interactive task {task['task_id']} as completed.")


# INTERACTIVE SESSION HELPER FUNCTIONS

def replace_placeholders(command: str, task_id: str) -> str:
    try:
        memory = get_interactive_memory(task_id)

        def first_or_none(key):
            val = memory.get(key, [])
            return val[0] if isinstance(val, list) and val else val if isinstance(val, str) else None

        known_values = {
            "share_name": first_or_none("known_shares"),
            "username": first_or_none("known_users"),
            "file_name": first_or_none("known_files"),
            "target_ip": memory.get("target") or "",
            "ip_address": memory.get("target") or "",
        }

        def substitute(match):
            raw_token = match.group(0)
            key = match.group(1).lower().replace("-", "_").replace(" ", "")
            value = known_values.get(key)

            if value:
                print(f"[~] Replacing {raw_token} → {value}")
                return value
            else:
                print(f"[!] Warning: Could not resolve placeholder {raw_token}. Stripping.")
                return ""

        # Match things like [target_IP], <TARGET_IP>, {file-name}, etc.
        pattern = r"[\[\{<]\s*([a-zA-Z0-9_\-\s]+)\s*[\]\}>]"
        command = re.sub(pattern, substitute, command)

        print(f"[DEBUG] Final command after fuzzy replacement: {repr(command)}")
        return command

    except Exception as e:
        print(f"[!] Exception in replace_placeholders: {e}")
        return command or ""
    
def merge_autonomy_hints(existing: list, incoming: list) -> list:
    seen = set()
    result = []
    for hint in existing + incoming:
        key = hint.strip().lower()
        if key not in seen:
            seen.add(key)
            result.append(hint.strip())
    return result


def looks_like_shell_prompt(output: str) -> bool:
    """
    Detects if the tmux output looks like a return to the user's shell prompt.
    Specifically looks for lines like '└─$' among the last few lines.
    """
    lines = output.strip().splitlines()[-5:]  # Look at the last 5 lines max
    for line in lines:
        stripped = line.strip()
        if stripped == "└─$":
            print(f"[~] Shell prompt detected on line: '{stripped}'")
            return True
    return False

def ensure_str(value, default="[not set]"):
    try:
        if isinstance(value, str):
            return value
        elif isinstance(value, list):
            return ", ".join(str(v) for v in value if v) or default
        elif value is None:
            return default
        else:
            return str(value)
    except Exception as e:
        print(f"[!] ensure_str failed on value: {value} — {e}")
        return default

def safe_join(items, fallback="[none]"):
    try:
        # Flatten nested lists just in case
        flat_items = []
        for i in items:
            if isinstance(i, list):
                flat_items.extend(map(str, i))
            else:
                flat_items.append(str(i))
        return ", ".join(flat_items) if flat_items else fallback
    except Exception as e:
        print(f"[!] Failed to join: {items} — {e}")
        return fallback

def extract_command_from_response(response_text):
    """
    Extracts the raw command from a structured LLM response.
    More fault-tolerant and sanitizes common formatting artifacts.

    Args:
        response_text (str): Full text returned by the LLM.

    Returns:
        str: The raw tool-specific command, or an empty string.
    """
    try:
        command = ""
        pattern = r"💻\s*Command:\s*(.+?)(?:\n|$)"
        match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)

        if match:
            command = match.group(1).strip()
        else:
            print("[!] Failed to extract command from LLM response.")
            return ""

        # 🧹 Clean up common formatting junk
        command = command.strip("`")
        command = command.replace("```plaintext", "")
        command = command.replace("```", "")
        command = command.strip()

        # ❌ Reject obviously invalid placeholder commands
        if re.search(r"<.*?>", command):
            print(f"[!] Ignoring placeholder command: {command}")
            return ""

        # ✅ Type safety check
        if not isinstance(command, str):
            print(f"[!] Unexpected type for command: {type(command)} — {repr(command)}")
            return ""

        return command

    except Exception as e:
        print(f"[!] Exception in extract_command_from_response: {e}")
        return ""

def init_interactive_memory(task):
    task_id = task["task_id"]
    memory_key = f"interactive:{task_id}:memory"

    if redis_client.exists(memory_key):
        print(f"[~] Memory already initialized for task {task_id}.")
        return

    # Use explicit enriched fields if present
    default_intent = f"Perform interactive enumeration using {task.get('tool', 'an unknown tool')}."
    default_subgoal = "Begin by exploring the interface and identifying useful commands."

    memory = {
        "intent": task.get("intent", default_intent),
        "subgoal": task.get("subgoal", default_subgoal),
        "last_reasoning": "",
        "known_shares": [],
        "known_files": [],
        "credentials_found": [],
        "errors": [],
        "last_command": ""
    }

    redis_client.set(memory_key, json.dumps(memory, indent=2))
    print(f"[+] Initialized memory for interactive task {task_id}.")

def get_interactive_memory(task_id):
    """
    Retrieves the Redis-backed memory for an interactive session.

    Args:
        task_id (str): The unique task identifier.

    Returns:
        dict: A dictionary representing the session memory.
              Returns a default empty structure if not found or invalid.
    """
    memory_key = f"interactive:{task_id}:memory"

    try:
        memory_json = redis_client.get(memory_key)
        if memory_json:
            memory = json.loads(memory_json)
            return memory
    except Exception as e:
        print(f"[!] Error loading memory for task {task_id}: {str(e)}")

    return {
        "intent": "",
        "subgoal": "",
        "last_reasoning": "",
        "known_shares": [],
        "known_files": [],
        "credentials_found": [],
        "errors": [],
        "last_command": ""
    }

def refresh_interactive_memory(task_or_info):
    task_id = task_or_info.get("task_id", None)
    target = task_or_info.get("target", "")
    service = task_or_info.get("service", "")
    port = str(task_or_info.get("port", ""))
    service_key = f"{service}_{port}".replace("?", "")

    updates = {}

    # Get recon data
    recon_data = json.loads(redis_client.get(f"recon_results:{target}") or "{}")
    for field in ["open_ports", "known_users", "known_shares", "known_files", "host_os_guess", "flags_found"]:
        if field in recon_data:
            updates.setdefault(field, []).extend(
                recon_data[field] if isinstance(recon_data[field], list) else [recon_data[field]]
            )

    # Get taskgen memory
    taskgen_data = json.loads(redis_client.get(f"taskgen:{target}:{service_key}:context") or "{}")
    for field in ["discovered_tools", "discovered_users", "discovered_files", "discovered_shares", "host_os_guess", "flags_found"]:
        if field in taskgen_data:
            key = field.replace("discovered_", "known_") if field.startswith("discovered_") else field
            updates.setdefault(key, []).extend(
                taskgen_data[field] if isinstance(taskgen_data[field], list) else [taskgen_data[field]]
            )

    # Only update Redis if task_id is present
    if task_id and updates:
        update_interactive_memory(task_id, updates)

def update_interactive_memory(task_id, update_dict):
    memory_key = f"interactive:{task_id}:memory"

    try:
        current = get_interactive_memory(task_id)
    except Exception as e:
        print(f"[!] Failed to retrieve memory for task {task_id}: {e}")
        current = {}

    normalized = {}
    log_entries = []

    for key, val in update_dict.items():
        try:
            # Overwrite mode for volatile fields like last_reasoning / last_command
            if key in ("last_reasoning", "last_command"):
                print(f"[~] Overwriting '{key}' instead of merging.")
                current[key] = val
                continue

            if key.endswith("_found"):
                norm_key = f"known_{key[:-6]}"
                print(f"[~] Normalizing '{key}' → '{norm_key}'")
            else:
                norm_key = key

            val = val if isinstance(val, list) else [val]

            if norm_key in ("known_shares", "shares_found"):
                val = [item.get("share_name", str(item)) if isinstance(item, dict) else item for item in val]
                filtered_val = []
                suspicious = []

                for share in val:
                    if isinstance(share, str):
                        stripped = share.strip()
                        if re.fullmatch(r"[\w$]+", stripped):
                            filtered_val.append(stripped)
                        else:
                            suspicious.append(share)

                if suspicious:
                    print(f"[!] Ignoring suspicious share(s): {suspicious}")
                    try:
                        log_dir = "logs/suspicious_shares"
                        os.makedirs(log_dir, exist_ok=True)
                        log_path = os.path.join(log_dir, f"{task_id}_suspicious_shares.log")
                        with open(log_path, "a") as f:
                            f.write(f"\n--- Suspicious Shares @ {datetime.utcnow().isoformat()}Z ---\n")
                            f.write(f"Attempted to add: {suspicious}\n")
                    except Exception as log_err:
                        print(f"[!] Failed to log suspicious shares: {log_err}")

                val = filtered_val

            normalized.setdefault(norm_key, []).extend(val)
            log_entries.append(f"[{task_id}] Updated memory field '{norm_key}' with values: {val}")

        except Exception as norm_err:
            print(f"[!] Failed to normalize key '{key}': {norm_err}")

    # ✅ Add Layer 1: Autonomy hint tracking based on known data
    discovered_keys = [
        k for k in normalized.keys()
        if k in ("known_shares", "known_files", "known_users", "known_flags", "known_vulnerabilities")
    ]
    if discovered_keys:
        hint_lines = [f"Explore newly discovered {k.replace('known_', '').replace('_', ' ')}." for k in discovered_keys]
        print(f"[+] Injecting autonomy_hint: {hint_lines}")
        normalized.setdefault("autonomy_hint", []).extend(hint_lines)

    # === Begin Layer 2 Modifications ===
    discoveries = {}

    # Merge normalized updates into current memory
    for key, new_values in normalized.items():
        try:
            existing = current.get(key, [])
            pre_merge_set = set(existing)
            merged_set = pre_merge_set.union(new_values)
            delta = list(merged_set - pre_merge_set)
            merged = list(merged_set)
            current[key] = merged

            if key.startswith("known_") and delta:
                increment_metric("memory_insights_added")
                discoveries[key] = delta  # ✅ Track only new items

        except Exception as merge_err:
            print(f"[!] Failed to merge values for key '{key}': {merge_err}")

    # ✅ Add autonomy hints for new discoveries only
    hint_map = {
        "known_shares": "Explore newly discovered shares.",
        "known_users": "Explore newly discovered users.",
        "known_flags": "Explore newly discovered flags.",
        "known_vulnerabilities": "Explore newly discovered vulnerabilities."
    }
    hints = [hint for field, hint in hint_map.items() if field in discoveries and discoveries[field]]

    if hints:
        print(f"[+] Injecting autonomy_hint: {hints}")
        existing_hints = current.get("autonomy_hint", [])
        current["autonomy_hint"] = merge_autonomy_hints(existing_hints, hints)
        log_entries.append(f"[{task_id}] Injected autonomy_hint: {hints}")

        # === Layer 3: Enhanced Logging for Autonomy Hints ===
    try:
        log_dir = "logs/autonomy_hints"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{task_id}_hints.log")

        with open(log_path, "a") as f:
            f.write(f"\n--- AUTONOMY HINTS @ {datetime.utcnow().isoformat()}Z ---\n")
            f.write(f"Triggered by new discoveries in: {list(discoveries.keys())}\n")
            for field, new_items in discoveries.items():
                f.write(f"- {field}: {new_items}\n")
            f.write(f"Injected hints:\n")
            for hint in hints:
                f.write(f"- {hint}\n")
            f.write("\n")
    except Exception as e:
        print(f"[!] Failed to write autonomy hint log for {task_id}: {e}")


    try:
        log_dir = "logs/memory_attribution"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{task_id}_memory_update.log")
        with open(log_path, "a") as f:
            f.write(f"\n--- MEMORY UPDATE @ {datetime.utcnow().isoformat()}Z ---\n")
            f.write("\n".join(log_entries) + "\n")
    except Exception as e:
        print(f"[!] Failed to write attribution log: {e}")

    try:
        for key in normalized.keys():
            existing = current.get(key)
            if not isinstance(existing, list):
                print(f"[!] Warning: Normalizing current[{key}] from {type(existing)} to list")
                current[key] = [existing] if existing else []

        for key, value in normalized.items():
            if isinstance(value, list):
                current_val = current.get(key, [])
                if not isinstance(current_val, list):
                    print(f"[!] Warning: Expected list for key '{key}' but got {type(current_val)}. Converting.")
                    current_val = [current_val] if current_val else []
                merged = list(set(current_val + value))
                current[key] = merged
            else:
                current[key] = value

        redis_client.set(memory_key, json.dumps(current, indent=2))

        with open(f"logs/{task_id}_memory.log", "a") as f:
            f.write(f"\n--- MEMORY @ {datetime.utcnow().isoformat()}Z ---\n")
            f.write(json.dumps(current, indent=2) + "\n")

    except Exception as e:
        print(f"[!] Failed to update Redis or write final memory log for task {task_id}: {e}")

def parse_output_and_update_memory(output, task, use_llm: bool = False):
    """
    Analyzes tool output and updates Redis memory with structured findings.
    Optionally uses the LLM to parse dynamically.

    Args:
        output (str): The captured terminal output from the tool.
        task (dict): The full task object.
        use_llm (bool): Whether to use LLM-based parsing.
    """
    task_id = task["task_id"]

    parsed_data = None
    if use_llm:
        task["output"] = output
        parsed_data = parse_output_with_llm(task)

        # 🔁 Fallback if LLM parsing returns nothing useful
        if not parsed_data or not any(parsed_data.get(k) for k in (
            "credentials_found", "flags_found", "users_found", "shares_found", "vulnerabilities_found", "host_os_guess"
        )):
            print(f"[!] Empty or unhelpful LLM output for task {task_id}. Falling back to regex.")
            return parse_output_and_update_memory(output, task, use_llm=False)

        parsed_data["output_summary"] = "Parsed successfully via LLM"
        parsed_data["output_quality"] = "normal"
        update_interactive_memory(task_id, parsed_data)
        print(f"[DEBUG] Parsing output (length={len(output)}):\n{repr(output[:200])}")
        return

    # === Legacy parser fallback ===
    discovered_files = []
    discovered_shares = []
    discovered_creds = []
    detected_errors = []
    failed_attempts = {}

    for line in output.splitlines():
        line = line.strip()

        if re.match(r"^[\w\-.]+\.(txt|log|cfg|conf|zip|db|bak)$", line, re.IGNORECASE):
            discovered_files.append(line)
        elif re.match(r"^[\w\-/]+/?$", line) and not line.startswith("Sharename") and "Type" not in line:
            if "/" in line or line.endswith("/"):
                discovered_files.append(line)

        if re.match(r"^\s*\w[\w\-\.]+\s+(Disk|IPC)", line):
            share = line.strip().split()[0]
            discovered_shares.append(share)

        if re.search(r"(user(name)?|login|pass(word)?)", line, re.IGNORECASE):
            discovered_creds.append(line)

        for err in ["NT_STATUS_", "access denied", "permission denied", "connection refused", "no such file"]:
            if err.lower() in line.lower():
                detected_errors.append(err.upper())

    # === Handle Empty Output as Poor Quality ===
    is_trivially_short = len(output.strip().splitlines()) < 2
    if is_trivially_short:
        detected_errors.append("TOOL_OUTPUT_TOO_SHORT")
        notes = ["Output had fewer than two lines — likely failure or empty response."]
        summary = "Empty or trivial output"
        quality = "poor"
    else:
        notes = []
        summary = "Parsed successfully via regex"
        quality = "normal"

    # === Dynamic failed resource inference ===
    if detected_errors:
        history_key = f"interactive:{task_id}:history"
        try:
            history_json = redis_client.get(history_key)
            if history_json:
                history = json.loads(history_json)
                last_cmd = next(
                    (entry["command"] for entry in reversed(history) if entry["command"] not in ("[session_start]", "")),
                    None
                )
                if last_cmd:
                    print(f"[DEBUG] Analyzing failed command for tracking: {last_cmd}")
                    if "smbclient" in last_cmd and "//" in last_cmd:
                        match = re.search(r"//[\d\.]+/([^\s/]+)", last_cmd)
                        if match:
                            share = match.group(1)
                            failed_attempts["tried_shares"] = [share]
                            print(f"[DEBUG] Detected failed share access: {share}")
                    elif re.search(r"(cat|less|more|tail)\s+\S+", last_cmd):
                        file_match = re.search(r"(cat|less|more|tail)\s+(\S+)", last_cmd)
                        if file_match:
                            path = file_match.group(2)
                            failed_attempts["tried_files"] = [path]
                            print(f"[DEBUG] Detected failed file access: {path}")
                    elif re.search(r"(enumdomusers|getent|id|whoami)", last_cmd):
                        failed_attempts["tried_users"] = ["*fallback*"]
                        print("[DEBUG] Detected failed user enumeration attempt.")
        except Exception as e:
            print(f"[!] Failed to infer failed resource from history: {e}")

    update_payload = {
        "known_files": discovered_files,
        "known_shares": discovered_shares,
        "credentials_found": discovered_creds,
        "errors": detected_errors,
        "notes": notes,
        "output_summary": summary,
        "output_quality": quality
    }

    update_payload.update(failed_attempts)
    update_interactive_memory(task_id, update_payload)

        # === Layer 3: Structured Logging ===
    try:
        log_dir = "logs/output_quality"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{task_id}_summary.log")

        with open(log_path, "a") as f:
            f.write(f"\n--- SUMMARY @ {datetime.utcnow().isoformat()}Z ---\n")
            f.write(f"Command: {task.get('command', '[unknown]')}\n")
            f.write(f"Output Quality: {quality}\n")
            f.write(f"Output Summary: {summary}\n")
            if notes:
                f.write(f"Notes:\n- " + "\n- ".join(notes) + "\n")
            if detected_errors:
                f.write(f"Errors:\n- " + "\n- ".join(detected_errors) + "\n")
            if failed_attempts:
                f.write(f"Inferred Failed Resources:\n")
                for k, v in failed_attempts.items():
                    f.write(f"- {k}: {v}\n")
            f.write("\n")

    except Exception as e:
        print(f"[!] Failed to write structured summary log for {task_id}: {e}")

def run():
    print("[+] Recon Agent is now running and waiting for tasks...")

    while True:
        task_data = redis_client.blpop(QUEUE_NAME, timeout=5)
        if not task_data:
            continue

        queue_name, task_json = task_data
        task = json.loads(task_json)

        print(f"[*] Received task {task['task_id']} for target {task['target']}")

        try:
            output = run_recon(task["target"])
            task["output"] = output
            task["status"] = "completed"
            print(f"[+] Recon task {task['task_id']} completed.")
        except Exception as e:
            task["output"] = f"[ERROR] {str(e)}"
            task["status"] = "error"
            print(f"[!] Error running recon task {task['task_id']}: {str(e)}")

        redis_client.set(f"task:{task['task_id']}", json.dumps(task))

if __name__ == "__main__":
    run()
