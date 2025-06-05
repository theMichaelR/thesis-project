import os
import json
from openai import OpenAI
from metrics import increment_metric
import uuid

# OpenAI API Key and Client Setup (do not change this part)
MODEL = "gpt-4o"
OPENAI_API_KEY = ("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    print("\n[Error] OpenAI API Key is missing! Set the OPENAI_API_KEY environment variable.")
    exit(1)
client = OpenAI(api_key=OPENAI_API_KEY)

def generate_command_from_task(target_ip: str, task_description: str) -> dict:
    """
    Given a high-level task description, return a dictionary with 'tool' and 'command'.
    The command should be ready to run in the terminal.
    """
    prompt = f"""
You are a penetration testing assistant.
The following task was generated for a host at {target_ip}:

\"{task_description}\"

Generate an appropriate command-line command that would accomplish this task.
Focus on real-world tools like Nmap, Gobuster, smbclient, etc that are installed on a kali linux machine.

Respond in the following JSON format only:
{{"tool": "tool_name", "command": "your command here"}}

Avoid explanation or extra text.
"""
    try:
        increment_metric("llm_calls_total")
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You are a command-line tool assistant for penetration testers."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=300,
        )
        reply = response.choices[0].message.content.strip()

        # Parse the output safely
        result = json.loads(reply)
        if "tool" in result and "command" in result:
            from recon_agent import replace_placeholders  # 👈 Import if not already
            temp_task_id = str(uuid.uuid4())              # 👈 For memory scoping
            result["command"] = replace_placeholders(result["command"], temp_task_id)
            return result
        else:
            print(f"[!] Unexpected format in LLM response. Falling back to raw command.")
            return {"tool": "unknown", "command": reply}

    except Exception as e:
        print(f"[!] Command generation failed for {target_ip}: {str(e)}")
        return {"tool": "error", "command": f"# ERROR: {str(e)}"}

def parse_output_with_llm(task: dict) -> dict:
    raw_output = task.get("output", "")
    if raw_output.strip() == "" or raw_output.strip() == task.get("command", "").strip():
        print(f"[{task['task_id']}] Skipping LLM parse: empty or echoed command only.")
        return {}

    tool = task.get("tool", "unknown")
    command = task.get("command", "").strip()

    prompt = f"""
You are a penetration testing assistant helping extract useful artifacts from command output.

A command has been executed during enumeration. Your job is to:
1. Think aloud in a scratchpad to analyze the output.
2. Return a clean JSON object with any structured data you find.

=== TOOL INFO ===
Tool: {tool}
Command: {command}

=== RAW OUTPUT ===
{raw_output.strip()}

=== SCRATCHPAD (think before you code) ===
- Carefully scan the output for usernames, shares, credentials, CVEs, or flags.
- If a table of shares is listed (e.g., smbclient -L), extract only the **Sharename** values (like WorkShares).
- If usernames are mentioned (e.g., administrator, kali), list them as users_found.
- Extract CVEs like CVE-2022-1234 or clear signs of vulnerabilities.
- Extract flags like HTB{{...}} or THM{{...}} if visible.

- Only extract data that literally appears in the output above.
- If no share or user list is shown, leave those fields empty.
- Do NOT infer values based on common names (e.g., WorkShares, IPC$).

=== JSON FORMAT (return only this) ===
{{
  "credentials_found": [...],
  "flags_found": [...],
  "users_found": [...],
  "shares_found": [...],
  "vulnerabilities_found": [...],
  "host_os_guess": "...",
  "notes": "..."
}}

Respond ONLY with the JSON. Do not include markdown, code blocks, or explanations.
""".strip()

    try:
        increment_metric("llm_calls_total")
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You extract structured findings from recon and enumeration output."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=750,
        )
        reply = response.choices[0].message.content.strip()

        if reply.startswith("```"):
            reply = reply.strip("`").lstrip("json").strip()
            if reply.endswith("```"):
                reply = reply[:-3].strip()

        parsed_data = json.loads(reply)

        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"{task['task_id']}_llm_parse.log")
        with open(log_path, "w") as f:
            f.write(f"--- TOOL: {tool} ---\n")
            f.write(f"--- COMMAND: {command} ---\n\n")
            f.write("=== RAW OUTPUT ===\n")
            f.write(raw_output.strip() + "\n\n")
            f.write("=== LLM RAW RESPONSE ===\n")
            f.write(reply + "\n\n")
            f.write("=== PARSED JSON ===\n")
            f.write(json.dumps(parsed_data, indent=2) + "\n")

        def clean_item(val):
            if not isinstance(val, str):
                val = str(val)
            val = val.strip()
            for prefix in ("Sharename:", "Username:", "Flag:", "User:", "Share:"):
                if val.lower().startswith(prefix.lower()):
                    return val[len(prefix):].strip()
            return val

        def ensure_string_list(value):
            if not isinstance(value, list):
                return []
            return [clean_item(v) for v in value if v is not None]

        # Ensure all expected fields are present and valid
        parsed_data["credentials_found"] = ensure_string_list(parsed_data.get("credentials_found", []))
        parsed_data["flags_found"] = ensure_string_list(parsed_data.get("flags_found", []))
        parsed_data["users_found"] = ensure_string_list(parsed_data.get("users_found", []))
        parsed_data["shares_found"] = ensure_string_list(parsed_data.get("shares_found", []))
        parsed_data["vulnerabilities_found"] = ensure_string_list(parsed_data.get("vulnerabilities_found", []))
        parsed_data["host_os_guess"] = str(parsed_data.get("host_os_guess", "") or "").strip()
        parsed_data["notes"] = str(parsed_data.get("notes", "") or "").strip()

        # Heuristic: Warn if reported shares don't appear in raw output
        hallucinated = [s for s in parsed_data["shares_found"] if s not in raw_output]
        if hallucinated:
            print(f"[{task['task_id']}] [⚠] Potential hallucinated shares: {hallucinated}")

        return parsed_data

    except Exception as e:
        print(f"[!] Failed to parse LLM output: {e}")
        return {}



