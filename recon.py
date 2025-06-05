import json
from task_router import create_task, enqueue_task


def main():
    print("=== Hackbot: Automated Pentesting ===")

    while True:
        print("\n[1] Start Recon")
        print("[2] Quit")
        choice = input("\nSelect an option: ").strip()

        if choice == "1":
            target_ip = input("\nEnter target IP or domain: ").strip()

            recon_task = create_task(
                task_type="recon",
                target=target_ip,
                description="Initial recon and enumeration task generation",
                manual_override=False
            )

            enqueue_task(recon_task)
            print(f"\n[+] Recon task queued with ID: {recon_task['task_id']}")
            print("[~] Monitor recon_agent.py and tmux_manager.py for progress.")

        elif choice == "2":
            print("\n[*] Exiting Hackbot. Goodbye!")
            break

        else:
            print("\n[-] Invalid option. Please try again.")


if __name__ == "__main__":
    main()
