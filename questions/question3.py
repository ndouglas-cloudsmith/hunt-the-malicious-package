import time
import urllib.request
import sys

# --- Password Protection ---
PASSWORD = "MAL-2022-7441"

def download_reward():
    reward_url = "https://raw.githubusercontent.com/ndouglas-cloudsmith/offsite-scripts/refs/heads/main/reward3.txt"
    save_as = "reward3.txt"
    try:
        print("\n📥 Downloading your reward file...")
        urllib.request.urlretrieve(reward_url, save_as)
        print(f"✅ Reward downloaded as '{save_as}'!")
    except Exception as e:
        print(f"❌ Failed to download the reward: {e}")

def password_protected():
    try:
        print("🚪 To access the second fragment, provide the the XYZ of the AI Models AIBOM.")
        
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
