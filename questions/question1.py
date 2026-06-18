import time
import urllib.request
import sys

# --- Password Protection ---
PASSWORD = "example-backend"

def download_reward():
    reward_url = "https://raw.githubusercontent.com/ndouglas-cloudsmith/offsite-scripts/refs/heads/main/reward1.txt"
    save_as = "reward1.txt"
    try:
        print("\n📥 Downloading your reward file...")
        urllib.request.urlretrieve(reward_url, save_as)
        print(f"✅ Reward downloaded as '{save_as}'!")
    except Exception as e:
        print(f"❌ Failed to download the reward: {e}")

def password_protected():
    try:
        print("🚪 To access the first fragment, provide the package name with the malicious package ID.")
        
        user_input = input("Password: ") 
        
        if user_input == PASSWORD:
            print("✅ Access granted! You found the correct flag.")
            time.sleep(1)
            download_reward()
        else:
            print("❌ Incorrect flag. Access denied.")
            time.sleep(1)
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n👋 Script closed by user. Goodbye!")
        sys.exit(0)

if __name__ == "__main__":
    password_protected()
