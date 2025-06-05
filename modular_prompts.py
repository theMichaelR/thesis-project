autonomy_hint = f"""
🧠 INTERACTION STRATEGY:

- When the session reveals new *resources* (e.g., shares, files, users, directories, or endpoints), suggest follow-up commands to interact with them.
- Examples:
    - For shares: connect and list contents.
    - For files: try reading them.
    - For users: probe for access or privilege info.
    - For unknown endpoints: enumerate supported methods or contents.

You are expected to *act* on these discoveries rather than just observe them.
"""

example_block = """
💡 EXAMPLE (Do not repeat this text. Use it to guide your command structure):

If the output revealed:
Shares: WorkShares
→ Suggest: smbclient \\\\target\\WorkShares -N

If the output revealed:
Files: flag.txt
→ Suggest: cat flag.txt

If the output revealed:
Users: admin
→ Suggest: rpcclient -U admin%'' target
"""
