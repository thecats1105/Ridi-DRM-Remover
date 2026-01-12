# Ridi-DRM-Remover

A CLI tool to decrypt purchased and downloaded ebooks from Ridibooks, converting them into DRM-free files (EPUB/PDF).

> **Disclaimer**
>
> All goods obtained through this software must not be shared, distributed, or sold. Any consequences resulting from the misuse of this software are solely the user's responsibility. Use at your own risk.

## Prerequisites

- **Python 3.8+**
- **Ridibooks Desktop App**: Books must be downloaded through the official app before they can be decrypted.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/thecats1105/Ridi-DRM-Remover.git
   cd Ridi-DRM-Remover
   ```

2. (Optional) Create and activate a virtual environment:

   ```bash
   python -m venv venv
   # Windows
   .\venv\Scripts\activate
   # macOS/Linux
   source venv/bin/activate
   ```

3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

The tool uses `ridi.py` as the main entry point.

### 1. Authentication (`auth`)

Before decrypting, you need to authenticate to store your `device_id` and `user_idx`.

```bash
python ridi.py auth login
```

- Follow the instructions to log in through the browser.
- Once logged in, copy the JSON data from the provided URL.
- Paste it back into the terminal and select the device where your books are downloaded.

**Other auth commands:**

- `python ridi.py auth list`: List saved accounts.
- `python ridi.py auth switch`: Switch the active account.
- `python ridi.py auth logout`: Remove account information.

### 2. List Books (`books`)

Scan your local library to see which books are available for decryption.

```bash
python ridi.py books
```

- **Filter by name**: `python ridi.py books -n "Aranya"`
- **Filter by ID**: `python ridi.py books -i "123456"`

### 3. Decrypt and Export (`export`)

Decrypt the downloaded books and save them to a specified directory.

```bash
# Export all downloaded books
python ridi.py export --all -o ./output

# Export specific book by ID
python ridi.py export -i "123456" -o ./output

# Export books matching a name
python ridi.py export -n "Title"
```

## Features

- **Multi-account support**: Manage multiple Ridi accounts. Device selection ensures the decryption data matches the specific device where the Ridi viewer is running.
- **Title Extraction**: Automatically extracts book titles from EPUB/PDF metadata for clean filenames.
- **EPUB & PDF Support**: Handles both major ebook formats provided by Ridibooks.
- **Safe Filenames**: Sanitizes titles to prevent filesystem errors.

## References

- [Retro-Rex8/Ridi-DRM-Remover](https://github.com/Retro-Rex8/Ridi-DRM-Remover)
- [hsj1/ridiculous](https://github.com/hsj1/ridiculous)
- This project is inspired by various community research on Ridi DRM.
