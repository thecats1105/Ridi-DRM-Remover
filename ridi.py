import argparse
import json
import urllib.parse
import webbrowser
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any
import ridi_utils

# Configuration and Constants
CONFIG_FILE = Path.home() / ".ridi_auth.json"
RIDI_LOGIN_URL = "https://ridibooks.com/account/login"
RIDI_USER_DEVICES_API = "https://account.ridibooks.com/api/user-devices/app"

class ConfigManager:
    def __init__(self, config_path: Path):
        self.config_path = config_path
        self.config = self._load()

    def _load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {"users": [], "active_user": None}
        try:
            return json.loads(self.config_path.read_text(encoding="utf-8"))
        except:
            return {"users": [], "active_user": None}

    def save(self):
        self.config_path.write_text(json.dumps(self.config, indent=2, ensure_ascii=False), encoding="utf-8")

    def add_user(self, user_idx: str, device_id: str, device_name: str, cookies: Dict[str, str]):
        # Check if user exists
        for user in self.config["users"]:
            if user["user_idx"] == str(user_idx) and user["device_id"] == device_id:
                user.update({
                    "device_name": device_name,
                    "cookies": cookies
                })
                self.config["active_user"] = self._get_user_id(user_idx, device_id)
                self.save()
                return

        new_user: Dict[str, Any] = {
            "id": self._get_user_id(user_idx, device_id),
            "user_idx": str(user_idx),
            "device_id": device_id,
            "device_name": device_name,
            "cookies": cookies
        }
        self.config["users"].append(new_user)
        self.config["active_user"] = new_user["id"]
        self.save()

    def _get_user_id(self, user_idx: str, device_id: str) -> str:
        return f"{user_idx}_{device_id[:8]}"

    def get_active_user(self) -> Optional[Dict[str, Any]]:
        if not self.config["active_user"]:
            return None
        for user in self.config["users"]:
            if user["id"] == self.config["active_user"]:
                return user
        return None
    
    def switch_user(self, user_id: str) -> bool:
        for user in self.config["users"]:
            if user["id"] == user_id:
                self.config["active_user"] = user_id
                self.save()
                return True
        return False
    
    def remove_user(self, user_id: str) -> bool:
        initial_len = len(self.config["users"])
        self.config["users"] = [u for u in self.config["users"] if u["id"] != user_id]
        if len(self.config["users"]) < initial_len:
            if self.config["active_user"] == user_id:
                self.config["active_user"] = self.config["users"][0]["id"] if self.config["users"] else None
            self.save()
            return True
        return False
    
    def list_users(self) -> List[Dict[str, Any]]:
        return self.config["users"]


class AuthCommand:
    def __init__(self, config_mgr: ConfigManager):
        self.config_mgr = config_mgr

    def login(self):
        # 1. Open URL with return_url set to the User Devices API
        callback_url = RIDI_USER_DEVICES_API
        state_payload = json.dumps({"return_url": callback_url}, separators=(',', ':'))
        target_url = f"{RIDI_LOGIN_URL}?state={urllib.parse.quote(state_payload)}"
        
        print(f"Opening browser to: {target_url}")
        print("\n=== Login Instructions ===")
        print("1. Log in to Ridi Books in the opened browser window.")
        print("2. After logging in, you will be redirected to a page showing JSON text (device list).")
        print("3. Copy ALL the JSON text displayed on that page.")
        print("4. Paste it below and press Enter.")
        
        webbrowser.open(target_url)
        
        try:
            print("\nPaste JSON > ", end="", flush=True)
            if sys.platform == 'win32':
                 # On Windows, sometimes massive paste can be an issue with standard input(), 
                 # but for this JSON size it's usually fine.
                 pass
            json_input = sys.stdin.readline().strip()
        except KeyboardInterrupt:
            return

        if not json_input:
            print("No data entered.")
            return

        self._process_device_list(json_input)

    def _process_device_list(self, json_str: str):
        try:
            # Handle user potentially pasting just the body or including headers by mistake, 
            # but we assume valid JSON string first.
            if not json_str.startswith("{"):
                 # Try to find start of JSON
                 start = json_str.find("{")
                 if start != -1:
                     json_str = json_str[start:]
            
            data = json.loads(json_str)
            devices = data.get("user_devices", [])
            
            if not devices:
                print("No devices found in the provided JSON.")
                return

            print("\nSelect the device you are using for this machine:")
            print(f"{'No.':<4} {'Device Name':<20} {'Device ID':<40} {'Code':<10} {'Last Used':<20}")
            print("-" * 100)
            
            for idx, dev in enumerate(devices):
                last_used_raw = dev.get('last_used')
                if last_used_raw:
                    try:
                        # Handle 'Z' suffix and set to local timezone
                        dt = datetime.fromisoformat(last_used_raw.replace('Z', '+00:00'))
                        last_used = dt.astimezone().strftime('%Y-%m-%d %H:%M:%S')
                    except Exception:
                        last_used = last_used_raw
                else:
                    last_used = 'N/A'
                print(f"{idx+1:<4} {dev.get('device_nick', 'Unknown'):<20} {dev.get('device_id'):<40} {dev.get('device_code'):<10} {last_used:<20}")
            
            while True:
                try:
                    line = input("\nEnter number: ")
                    sel = int(line)
                    if 1 <= sel <= len(devices):
                        target = devices[sel-1]
                        break
                    print("Invalid selection.")
                except ValueError:
                    print("Please enter a number.")
            
            user_idx = target.get("user_idx")
            device_id = target.get("device_id")
            device_name = target.get("device_nick")
            
            if user_idx and device_id:
                # We don't have cookies anymore, pass empty dict
                self.config_mgr.add_user(user_idx, device_id, device_name, {})
                print(f"Successfully added user {user_idx} (Device: {device_id})")
            else:
                print("Error: Invalid device data in selection.")
                
        except json.JSONDecodeError:
            print("Invalid JSON format. Please ensure you copied the text correctly.")
        except Exception as e:
            print(f"Error processing data: {e}")

    def switch(self):
        users = self.config_mgr.list_users()
        if not users:
            print("No users found.")
            return

        print("\nRegistered Users:")
        for idx, user in enumerate(users):
            active = "*" if user["id"] == self.config_mgr.config.get("active_user") else " "
            print(f"{active} {idx+1}. {user['user_idx']} ({user['device_name']})")
        
        try:
            sel = int(input("\nSelect user to switch to: "))
            if 1 <= sel <= len(users):
                target_user = users[sel-1]
                if self.config_mgr.switch_user(target_user["id"]):
                    print(f"Switched to user {target_user['user_idx']}")
            else:
                print("Invalid selection.")
        except ValueError:
            print("Invalid input.")

    def list_accounts(self):
        users = self.config_mgr.list_users()
        if not users:
            print("No users found.")
            return
        print("\nRegistered Users:")
        for user in users:
            active = "*" if user["id"] == self.config_mgr.config.get("active_user") else " "
            print(f"{active} [{user['id']}] User: {user['user_idx']}, Device: {user['device_name']}")

    def logout(self):
        active_user_id = self.config_mgr.config.get("active_user")
        if not active_user_id:
            print("No active user.")
            return
        if self.config_mgr.remove_user(active_user_id):
            print("User removed.")
        else:
            print("Failed to remove user.")


class BooksCommand:
    def __init__(self, config_mgr: ConfigManager):
        self.config_mgr = config_mgr

    def run(self, name_filter: Optional[str] = None, id_filter: Optional[str] = None):
        active = self.config_mgr.get_active_user()
        if not active:
            print("No active user. Please login first.")
            return
        
        user_idx = active["user_idx"]
        device_id = active["device_id"]
        
        try:
            lib_path = ridi_utils.library_path(user_idx)
            if not lib_path.exists():
                print(f"Library path not found for user {user_idx}: {lib_path}")
                return

            infos = ridi_utils.book_infos(lib_path)
            # Filter out books without .dat files
            infos = [b for b in infos if b.file_path(ridi_utils.FileKind.DATA).exists()]
            
            if not infos:
                print("No books found in library.")
                return
            
            # Filter by ID first if provided
            if id_filter:
                infos = [b for b in infos if b.id == id_filter]
                if not infos:
                    print(f"No books found with ID: {id_filter}")
                    return

            results: List[tuple[str, str]] = []
            
            print(f"Scanning {len(infos)} books for metadata...", file=sys.stderr)
            
            for i, book in enumerate(infos):
                try:
                    # Print progress
                    print(f"\rProcessing {i+1}/{len(infos)}: {book.id}", end="", file=sys.stderr)
                    
                    key = ridi_utils.decrypt_key(book, device_id)
                    book_content = ridi_utils.decrypt_book(book, key)
                    title = ridi_utils.extract_title(book.format, book_content) or "Unknown Title"
                    
                    if name_filter and name_filter not in title:
                        continue
                        
                    results.append((book.id, title))
                except Exception as e:
                    # If we can't decrypt or read, maybe just list ID
                    if not name_filter:
                        results.append((book.id, f"[Error: {e}]"))
            
            print("\r" + " " * 50 + "\r", end="", file=sys.stderr) # Clear progress line
            
            if not results:
                print("No books matched criteria.")
                return

            print(f"{'ID':<12} | {'Title'}")
            print("-" * 60)
            for bid, btitle in results:
                print(f"{bid:<12} | {btitle}")
                
        except Exception as e:
            print(f"Error: {e}")


class ExportCommand:
    def __init__(self, config_mgr: ConfigManager):
        self.config_mgr = config_mgr

    def run(self, output_dir: str, name_filter: Optional[str] = None, id_filter: Optional[str] = None, run_all: bool = False):
        active = self.config_mgr.get_active_user()
        if not active:
            print("No active user. Please login first.")
            return
        
        user_idx = active["user_idx"]
        device_id = active["device_id"]
        
        try:
            lib_path = ridi_utils.library_path(user_idx)
            if not lib_path.exists():
                print(f"Library path not found for user {user_idx}: {lib_path}")
                print("Ensure you have downloaded books via the Ridi Reader app.")
                return

            infos = ridi_utils.book_infos(lib_path)
            # Filter out books without .dat files
            infos = [b for b in infos if b.file_path(ridi_utils.FileKind.DATA).exists()]

            if not infos:
                print("No books found in library.")
                return
            
            # Filter candidates 
            candidates: List[ridi_utils.BookInfo] = []
            
            # If ID filter is on, we can filter immediately
            if id_filter:
                infos = [b for b in infos if b.id == id_filter]
            
            if not infos:
                print("No matching books found (ID filter).")
                return

            # If name filter is on, we need to inspect titles
            if name_filter:
                print("Scanning books to match title...")
                for book in infos:
                    try:
                        key = ridi_utils.decrypt_key(book, device_id)
                        book_content = ridi_utils.decrypt_book(book, key)
                        title = ridi_utils.extract_title(book.format, book_content)
                        if title and name_filter in title:
                            candidates.append(book)
                    except:
                        continue
            else:
                candidates = infos

            # Determine what to export
            # If explicit filters are given (-n or -i), we export matched.
            # If no filters given, we check for --all.
            # If no filters and no --all, what is default?
            # Instructions: "--all ... to export ALL".
            # This implies if NO flags, maybe it shouldn't export?
            # But commonly we preserve "export all by default" or "require arguments".
            # The prompt says: "add --all argument to export all downloaded books".
            # Current behavior is export all.
            # I will assume:
            # If filters are present -> export matches.
            # If no filters:
            #    If --all is present -> export all.
            #    If --all is NOT present -> export all (default behavior) or maybe Ask?
            # To be safe and user friendly: Default to ALL implies --all isn't strictly needed for behavior "export all",
            # but maybe the user wants to force explicit "all".
            # However, if I implement filters, "no filters" usually means "everything".
            # Let's keep it simple: "candidates" contains everything after filtering.
            
            if not candidates:
                print("No books found matching criteria.")
                return

            print(f"Found {len(candidates)} books. Preparing to export...")
            
            # Prepare output directory
            out_path = Path(output_dir)
            if not out_path.exists():
                try:
                    out_path.mkdir(parents=True, exist_ok=True)
                    print(f"Created output directory: {out_path}")
                except Exception as e:
                    print(f"Failed to create output directory: {e}")
                    return
            
            # Strategy: Change CWD to output_dir, run decrypt, then change back.
            original_cwd = os.getcwd()
            os.chdir(out_path)
            
            success_count = 0
            try:
                for book_info in candidates:
                    if ridi_utils.decrypt_with_progress(book_info, device_id, debug=False):
                        success_count += 1
            finally:
                os.chdir(original_cwd)
                
            print(f"\nExport completed. {success_count}/{len(candidates)} books exported to {out_path}")
            
        except Exception as e:
            print(f"Error during export: {e}")


def main():
    parser = argparse.ArgumentParser(prog="ridi", description="Ridi Books DRM Remover CLI Utility")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Auth commands
    auth_parser = subparsers.add_parser("auth", help="Manage authentication")
    auth_subparsers = auth_parser.add_subparsers(dest="auth_command")
    auth_subparsers.add_parser("login", help="Login to Ridi account")
    auth_subparsers.add_parser("logout", help="Logout current account")
    auth_subparsers.add_parser("switch", help="Switch between accounts")
    auth_subparsers.add_parser("list", help="List accounts")
    
    # Books command
    books_parser = subparsers.add_parser("books", help="List downloaded books")
    books_parser.add_argument("-n", "--name", help="Filter by book title (partial match)")
    books_parser.add_argument("-i", "--id", help="Filter by book ID (exact match)")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export and decrypt books")
    export_parser.add_argument("-o", "--output", default=".", help="Output directory (default: current)")
    export_parser.add_argument("-n", "--name", help="Export books matching title (partial match)")
    export_parser.add_argument("-i", "--id", help="Export book matching ID (exact match)")
    export_parser.add_argument("-a", "--all", action="store_true", help="Export all books")
    
    args = parser.parse_args()
    
    config_mgr = ConfigManager(CONFIG_FILE)
    
    try:
        if args.command == "auth":
            cmd = AuthCommand(config_mgr)
            if args.auth_command == "login":
                cmd.login()
            elif args.auth_command == "switch":
                cmd.switch()
            elif args.auth_command == "logout":
                cmd.logout()
            elif args.auth_command == "list":
                cmd.list_accounts()
            else:
                auth_parser.print_help()
        
        elif args.command == "books":
            cmd = BooksCommand(config_mgr)
            cmd.run(name_filter=args.name, id_filter=args.id)
                
        elif args.command == "export":
            # Show help if no filtering or "all" argument is provided
            if not any([args.all, args.name, args.id]):
                export_parser.print_help()
            else:
                cmd = ExportCommand(config_mgr)
                cmd.run(args.output, name_filter=args.name, id_filter=args.id, run_all=args.all)
            
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
if __name__ == "__main__":
    main()
