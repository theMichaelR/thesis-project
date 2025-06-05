from openai import OpenAI
from metrics import get_all_metrics
import json
import os

# OpenAI API Key and Client Setup (do not change this part)
MODEL = "gpt-4o"
OPENAI_API_KEY = ("OPENAI_API_KEY")
if not OPENAI_API_KEY:
    print("\n[Error] OpenAI API Key is missing! Set the OPENAI_API_KEY environment variable.")
    exit(1)
client = OpenAI(api_key=OPENAI_API_KEY)

# Optional: Allow CLI argument for file path
DEFAULT_JSON_PATH = "/home/kali/Code/recon_results"

def load_final_json(path=DEFAULT_JSON_PATH):
    if os.path.isdir(path):
        # Look for files that end in "_final.json"
        for file in os.listdir(path):
            if file.endswith("_final.json"):
                full_path = os.path.join(path, file)
                with open(full_path, "r") as f:
                    return json.load(f)
        raise FileNotFoundError("No *_final.json file found in directory.")
    else:
        with open(path, "r") as f:
            return json.load(f)

def extract_report_context(final_json):
    """
    Extract high-value fields from final.json to insert into the LLM prompt.
    """
    target = final_json.get("target", "unknown")
    open_ports = final_json.get("open_ports", [])
    services = final_json.get("services", {})

    context = {
        "target": target,
        "open_ports": open_ports,
        "services": services,
        # You could later inject additional metrics here
        "metrics": {
            "interactive_sessions_opened": None,
            "llm_calls_total": None,
            "memory_insights_added": None
        },
    }

    return context

def inject_metrics_from_redis(context):
    metrics = get_all_metrics()
    context["metrics"].update({
        "interactive_sessions_opened": metrics.get("interactive_sessions_opened", 0),
        "llm_calls_total": metrics.get("llm_calls_total", 0),
        "memory_insights_added": metrics.get("memory_insights_added", 0),
    })

def generate_markdown_report(final_json_path):
    final_json = load_final_json(final_json_path)
    context = extract_report_context(final_json)

    # Inject metrics from Redis here
    inject_metrics_from_redis(context)

    prompt = build_prompt(context)
    markdown = call_llm(prompt)
    save_markdown_report(markdown, context["target"])

def build_prompt(context):
    """
    Construct a detailed prompt for generating a high-quality Markdown recon report.
    """
    target = context["target"]
    ports = context["open_ports"]
    services = context["services"]
    metrics = context["metrics"]

    port_summary = ", ".join([f"{p}" for p in ports])

    # Flatten tools
    tools_used = set()
    users_found = set()
    shares_found = set()
    vulns = set()

    for svc in services.values():
        for task in svc.get("enumeration_tasks", []):
            tool = task.get("tool", "")
            if tool:
                tools_used.add(tool)
            output = task.get("output", "")
            if "administrator" in output or "guest" in output or "kali" in output:
                users_found.update(["administrator", "guest", "kali"])
            if "ADMIN$" in output or "IPC$" in output or "C$" in output or "WorkShares" in output:
                shares_found.update(["ADMIN$", "IPC$", "C$", "WorkShares"])
            if "CVE-" in output:
                for word in output.split():
                    if word.startswith("CVE-"):
                        vulns.add(word.strip(",:.;"))

    tools = ", ".join(sorted(tools_used))
    users = ", ".join(sorted(users_found))
    shares = ", ".join(sorted(shares_found))
    cves = ", ".join(sorted(vulns)) if vulns else "None observed"

    return f"""
You are a cybersecurity analyst. Based on the following enumeration data from an automated recon scan, write a professional Markdown report with the following structure:

## 🔍 Reconnaissance Summary Report: {target}

### 🎯 Target Overview

- IP Address: {target}
- Open Ports: {port_summary}

### 🧩 Service-Specific Findings

Summarize findings per port/service. Note which tools were used, what shares, users, or errors appeared. Do not make up findings. Pull real examples from memory if available.

### 🧑‍🤝‍🧑 Users Identified

From tools like enum4linux, rpcclient, or memory output:
{users or 'None found'}

### 📁 Shares Identified

Reported by smbclient, enum4linux, or rpcclient:
{shares or 'None listed'}

### ⚠️ Vulnerabilities & Errors

If any CVEs were mentioned (even if hallucinated), list them.
Mention notable errors like `ACCESS_DENIED`, `NT_STATUS_`, malformed enum4linux targets, etc.

CVE Mentions: {cves}

### ✅ Enumeration Task Stats

- Interactive Sessions Opened: {metrics['interactive_sessions_opened']}
- LLM Calls Made: {metrics['llm_calls_total']}
- Memory Insights Added: {metrics['memory_insights_added']}
- Tools Used: {tools or 'unknown'}

### 📌 Next Recommended Steps

Give 3–5 concrete next steps. Base them only on what’s known from this report.
    """.strip()

def call_llm(prompt: str) -> str:
    print("[*] Sending prompt to LLM...")

    response = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.4,
        max_tokens=2048,
    )

    markdown = response.choices[0].message.content.strip()
    print("[+] Markdown report generated.")
    return markdown

def save_markdown_report(markdown: str, target: str):
    filename = f"report_{target.replace('.', '_')}.md"
    path = os.path.join(DEFAULT_JSON_PATH, filename)

    with open(path, "w") as f:
        f.write(markdown)

    print(f"[+] Markdown report saved to: {path}")

if __name__ == "__main__":
    generate_markdown_report(DEFAULT_JSON_PATH)
