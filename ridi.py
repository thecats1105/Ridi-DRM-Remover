"""
Main entry point for Ridi Books DRM Remover CLI Utility.
Provides commands for authentication, listing books, and exporting decrypted files.
"""

# Nuitka build flags:
# nuitka-project: --onefile
# nuitka-project: --output-dir=dist

import argparse
import json
import logging
import sys
import urllib.parse
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast

import ridi_utils
import ridi_types

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("ridi")

# Configuration and Constants
CONFIG_FILE = Path.home() / ".ridi_auth.json"
RIDI_LOGIN_URL = "https://ridibooks.com/account/login"
RIDI_USER_DEVICES_API = "https://account.ridibooks.com/api/user-devices/app"


class ConfigManager:
    """Manages user authentication configuration."""

    def __init__(self, config_path: Path):
        self.config_path: Path = config_path
        self.config: ridi_types.ConfigData = self._load()

    def _load(self) -> ridi_types.ConfigData:
        """Load configuration from file."""
        if not self.config_path.exists():
            return {"users": [], "active_user": None}
        try:
            return cast(
                ridi_types.ConfigData,
                json.loads(self.config_path.read_text(encoding="utf-8")),
            )
        except (json.JSONDecodeError, OSError):
            return {"users": [], "active_user": None}

    def save(self):
        """Save configuration to file."""
        try:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            self.config_path.write_text(
                json.dumps(self.config, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except OSError as e:
            logger.error("Failed to save config: %s", e)

    def add_user(
        self,
        user_idx: str,
        device_id: str,
        device_name: str | None,
        cookies: dict[str, str],
    ):
        """Add or update a user in the configuration."""
        # Check if user exists
        for user in self.config["users"]:
            if user["user_idx"] == str(user_idx) and user["device_id"] == device_id:
                user.update(
                    {"device_name": device_name or "Unknown Device", "cookies": cookies}
                )
                self.config["active_user"] = self._get_user_id(user_idx, device_id)
                self.save()
                return

        new_user: ridi_types.UserData = {
            "id": self._get_user_id(user_idx, device_id),
            "user_idx": user_idx,
            "device_id": device_id,
            "device_name": device_name or "Unknown Device",
            "cookies": cookies,
        }
        self.config["users"].append(new_user)
        self.config["active_user"] = new_user["id"]
        self.save()

    def _get_user_id(self, user_idx: str, device_id: str) -> str:
        """Generate a unique ID for a user/device pair."""
        return f"{user_idx}_{device_id[:8]}"

    def get_active_user(self) -> ridi_types.UserData | None:
        """Get the currently active user configuration."""
        if not self.config["active_user"]:
            return None
        for user in self.config["users"]:
            if user["id"] == self.config["active_user"]:
                return user
        return None

    def switch_user(self, user_id: str) -> bool:
        """Switch the active user."""
        for user in self.config["users"]:
            if user["id"] == user_id:
                self.config["active_user"] = user_id
                self.save()
                return True
        return False

    def remove_user(self, user_id: str) -> bool:
        """Remove a user from the configuration."""
        initial_len = len(self.config["users"])
        self.config["users"] = [u for u in self.config["users"] if u["id"] != user_id]
        if len(self.config["users"]) < initial_len:
            if self.config["active_user"] == user_id:
                self.config["active_user"] = (
                    self.config["users"][0]["id"] if self.config["users"] else None
                )
            self.save()
            return True
        return False

    def list_users(self) -> list[ridi_types.UserData]:
        """List all registered users."""
        return self.config["users"]


class AuthCommand:
    """Handles authentication commands."""

    def __init__(self, config_mgr: ConfigManager):
        self.config_mgr: ConfigManager = config_mgr

    def login(self):
        """Perform login by opening a browser and processing device list JSON."""
        # 1. Open URL with return_url set to the User Devices API
        callback_url = RIDI_USER_DEVICES_API
        state_payload = json.dumps({"return_url": callback_url}, separators=(",", ":"))
        state_q = urllib.parse.quote(state_payload)
        target_url = f"{RIDI_LOGIN_URL}?state={state_q}"

        logger.info("Opening browser to: %s", target_url)
        logger.info("\n=== Login Instructions ===")
        logger.info("1. Log in to Ridi Books in the opened browser window.")
        logger.info(
            "2. After logging in, you will be redirected to a page "
            + "showing JSON text (device list)."
        )
        logger.info("3. Copy ALL the JSON text displayed on that page.")
        logger.info("4. Paste it below and press Enter.")

        webbrowser.open(target_url)

        try:
            print("\nPaste JSON > ", end="", flush=True)
            json_input = sys.stdin.readline().strip()
        except KeyboardInterrupt:
            return

        if not json_input:
            logger.warning("No data entered.")
            return

        self._process_device_list(json_input)

    def _format_last_used(self, last_used_raw: str | None) -> str:
        """Format the 'last_used' timestamp."""
        if not last_used_raw:
            return "N/A"
        try:
            # Handle 'Z' suffix and set to local timezone
            dt = datetime.fromisoformat(last_used_raw.replace("Z", "+00:00"))
            return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            return last_used_raw

    def _display_devices(self, devices: list[ridi_types.UserDevice]):
        """Display the list of devices."""
        print("\nSelect the device you are using for this machine:")
        print(
            f"{'No.':<4} {'Device Name':<20} {'Device ID':<40} {'Code':<10} {'Last Used':<20}"
        )
        print("-" * 100)

        for idx, dev in enumerate(devices):
            last_used = self._format_last_used(dev.get("last_used"))
            print(
                f"{idx + 1:<4} {dev.get('device_nick', 'Unknown'):<20} "
                + f"{dev.get('device_id'):<40} {dev.get('device_code'):<10} {last_used:<20}"
            )

    def _select_device(
        self, devices: list[ridi_types.UserDevice]
    ) -> ridi_types.UserDevice:
        """Prompt user to select a device from the list."""
        while True:
            try:
                line = input("\nEnter number: ")
                sel = int(line)
                if 1 <= sel <= len(devices):
                    return devices[sel - 1]
                logger.warning("Invalid selection.")
            except ValueError:
                logger.warning("Please enter a number.")

    def _process_device_list(self, json_str: str):
        """Process the device list JSON and add selected device to config."""
        try:
            # Handle user potentially pasting extra text
            if not json_str.startswith("{"):
                start = json_str.find("{")
                if start != -1:
                    json_str = json_str[start:]

            data = cast(ridi_types.UserDevices, json.loads(json_str))
            devices = data.get("user_devices", [])

            if not devices:
                logger.error("No devices found in the provided JSON.")
                return

            self._display_devices(devices)
            target = self._select_device(devices)

            user_idx = str(target.get("user_idx"))
            device_id = target.get("device_id")
            device_name = target.get("device_nick")

            if user_idx and device_id:
                # We don't have cookies anymore, pass empty dict
                self.config_mgr.add_user(user_idx, device_id, device_name, {})
                logger.info(
                    "Successfully added user %s (Device: %s)", user_idx, device_id
                )
            else:
                logger.error("Error: Invalid device data in selection.")

        except json.JSONDecodeError:
            logger.error(
                "Invalid JSON format. Please ensure you copied the text correctly."
            )
        except Exception as e:
            logger.error("Error processing data: %s", e)

    def switch(self):
        """Switch between registered accounts."""
        users = self.config_mgr.list_users()
        if not users:
            logger.info("No users found.")
            return

        print("\nRegistered Users:")
        for idx, user in enumerate(users):
            is_active = user["id"] == self.config_mgr.config.get("active_user")
            active = "*" if is_active else " "
            print(f"{active} {idx + 1}. {user['user_idx']} ({user['device_name']})")

        try:
            sel = int(input("\nSelect user to switch to: "))
            if 1 <= sel <= len(users):
                target_user = users[sel - 1]
                if self.config_mgr.switch_user(target_user["id"]):
                    logger.info("Switched to user %s", target_user["user_idx"])
            else:
                logger.warning("Invalid selection.")
        except ValueError:
            logger.error("Invalid input.")

    def list_accounts(self):
        """List all registered accounts."""
        users = self.config_mgr.list_users()
        if not users:
            logger.info("No users found.")
            return
        print("\nRegistered Users:")
        for user in users:
            is_active = user["id"] == self.config_mgr.config.get("active_user")
            active = "*" if is_active else " "
            print(
                f"{active} [{user['id']}] User: {user['user_idx']}, "
                + f"Device: {user['device_name']}"
            )

    def logout(self):
        """Logout the current active account."""
        active_user_id = self.config_mgr.config.get("active_user")
        if not active_user_id:
            logger.info("No active user.")
            return
        if self.config_mgr.remove_user(active_user_id):
            logger.info("User removed.")
        else:
            logger.error("Failed to remove user.")


class BooksCommand:
    """Handles book listing commands."""

    def __init__(self, config_mgr: ConfigManager):
        self.config_mgr: ConfigManager = config_mgr

    def run(self, name_filter: str | None = None, id_filter: str | None = None):
        """List downloaded books matching the filters."""
        active = self.config_mgr.get_active_user()
        if not active:
            logger.error("No active user. Please login first.")
            return

        user_idx = active["user_idx"]
        device_id = active["device_id"]

        try:
            infos = self._get_library_books(user_idx)
            if not infos:
                return

            if id_filter:
                infos = [b for b in infos if b.id == id_filter]
                if not infos:
                    logger.warning("No books found with ID: %s", id_filter)
                    return

            results = self._scan_book_titles(infos, device_id, name_filter)

            if not results:
                logger.warning("No books matched criteria.")
                return

            self._display_books(results)

        except Exception as e:
            logger.error("Error: %s", e)

    def _get_library_books(self, user_idx: str) -> list[ridi_utils.BookInfo]:
        """Get list of books from library path."""
        lib_path = ridi_utils.library_path(user_idx)
        if not lib_path.exists():
            logger.error("Library path not found for user %s: %s", user_idx, lib_path)
            return []

        infos = ridi_utils.book_infos(lib_path)
        # Filter out books without .dat files
        infos = [b for b in infos if b.get_file(ridi_utils.FileKind.DATA).exists()]

        if not infos:
            logger.warning("No books found in library.")
        return infos

    def _scan_book_titles(
        self,
        infos: list[ridi_utils.BookInfo],
        device_id: str,
        name_filter: str | None,
    ) -> list[tuple[str, str]]:
        """Scan books for titles and apply filter."""
        results: list[tuple[str, str]] = []
        logger.info("Scanning %d books for metadata...", len(infos))

        for i, book in enumerate(infos):
            try:
                # Print progress to stderr to keep stdout clean
                print(
                    f"\rProcessing {i + 1}/{len(infos)}: {book.id}",
                    end="",
                    file=sys.stderr,
                )

                key = ridi_utils.decrypt_key(book, device_id)
                book_content = ridi_utils.decrypt_book(book, key)
                title = (
                    ridi_utils.extract_title(book.format, book_content)
                    or "Unknown Title"
                )

                if name_filter and name_filter not in title:
                    continue

                results.append((book.id, title))
            except Exception as e:
                if not name_filter:
                    results.append((book.id, f"[Error: {e}]"))

        print("\r" + " " * 50 + "\r", end="", file=sys.stderr)  # Clear progress line
        return results

    def _display_books(self, results: list[tuple[str, str]]):
        """Display the list of books in a table."""
        print(f"{'ID':<12} | {'Title'}")
        print("-" * 60)
        for bid, btitle in results:
            print(f"{bid:<12} | {btitle}")


class ExportCommand:
    """Handles book export and decryption commands."""

    def __init__(self, config_mgr: ConfigManager):
        self.config_mgr: ConfigManager = config_mgr

    def run(
        self,
        output_dir: str,
        name_filter: str | None = None,
        id_filter: str | None = None,
    ):
        """Export and decrypt books matching the filters."""
        active = self.config_mgr.get_active_user()
        if not active:
            logger.error("No active user. Please login first.")
            return

        user_idx = active["user_idx"]
        device_id = active["device_id"]

        try:
            infos = self._get_exportable_books(user_idx)
            if not infos:
                return

            candidates = self._filter_candidates(
                infos, device_id, name_filter, id_filter
            )
            if not candidates:
                logger.warning("No books found matching criteria.")
                return

            logger.info("Found %d books. Preparing to export...", len(candidates))
            out_path = Path(output_dir)
            out_path.mkdir(parents=True, exist_ok=True)

            success_count = self._export_books(candidates, device_id, out_path)
            logger.info(
                "\nExport completed. %d/%d books exported to %s",
                success_count,
                len(candidates),
                out_path.absolute(),
            )

        except Exception as e:
            logger.error("Error during export: %s", e)

    def _get_exportable_books(self, user_idx: str) -> list[ridi_utils.BookInfo]:
        """Retrieve the list of books that can be exported."""
        lib_path = ridi_utils.library_path(user_idx)
        if not lib_path.exists():
            logger.error("Library path not found for user %s: %s", user_idx, lib_path)
            logger.info("Ensure you have downloaded books via the Ridi Reader app.")
            return []

        infos = ridi_utils.book_infos(lib_path)
        # Filter out books without .dat files
        infos = [b for b in infos if b.get_file(ridi_utils.FileKind.DATA).exists()]

        if not infos:
            logger.warning("No books found in library.")
        return infos

    def _filter_candidates(
        self,
        infos: list[ridi_utils.BookInfo],
        device_id: str,
        name_filter: str | None,
        id_filter: str | None,
    ) -> list[ridi_utils.BookInfo]:
        """Filter the list of books based on ID and name filters."""
        if id_filter:
            infos = [b for b in infos if b.id == id_filter]
            if not infos:
                logger.warning("No matching books found (ID filter).")
                return []

        if not name_filter:
            return infos

        candidates: list[ridi_utils.BookInfo] = []
        logger.info("Scanning books to match title...")
        for book in infos:
            try:
                key = ridi_utils.decrypt_key(book, device_id)
                book_content = ridi_utils.decrypt_book(book, key)
                title = ridi_utils.extract_title(book.format, book_content)
                if title and name_filter in title:
                    candidates.append(book)
            except Exception:
                continue
        return candidates

    def _export_books(
        self, candidates: list[ridi_utils.BookInfo], device_id: str, out_path: Path
    ) -> int:
        """Execute the export for each candidate."""
        success_count = 0
        for book_info in candidates:
            if ridi_utils.decrypt_with_progress(
                book_info, device_id, debug=False, output_dir=out_path
            ):
                success_count += 1
        return success_count


class CLIArgs(Protocol):
    command: str | None
    auth_command: str | None
    name: str | None
    id: str | None
    output: str
    all: bool


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ridi", description="Ridi Books DRM Remover CLI Utility"
    )
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
    books_parser.add_argument(
        "-n", "--name", help="Filter by book title (partial match)"
    )
    books_parser.add_argument("-i", "--id", help="Filter by book ID (exact match)")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export and decrypt books")
    export_parser.add_argument(
        "-o", "--output", default=".", help="Output directory (default: current)"
    )
    export_parser.add_argument(
        "-n", "--name", help="Export books matching title (partial match)"
    )
    export_parser.add_argument(
        "-i", "--id", help="Export book matching ID (exact match)"
    )
    export_parser.add_argument(
        "-a", "--all", action="store_true", help="Export all books"
    )

    args = cast(CLIArgs, cast(object, parser.parse_args()))

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
                cmd.run(args.output, name_filter=args.name, id_filter=args.id)

        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
