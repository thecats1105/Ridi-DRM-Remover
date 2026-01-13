"""
Utility module for Ridi Books DRM removal.
Provides functionality for finding library paths, decrypting keys, and decrypting book files.
"""
import io
import logging
import os
import re
import sys
import zipfile
from enum import Enum
from pathlib import Path
from typing import List, Optional
from xml.etree import ElementTree as ET

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logger
logger = logging.getLogger("ridi_utils")


class BookFormat(Enum):
    """Supported book formats."""
    EPUB = "epub"
    PDF = "pdf"

    @classmethod
    def from_path(cls, path: Path) -> 'BookFormat':
        """Determine book format from file extension."""
        ext = path.suffix[1:].lower()
        if ext == "epub":
            return cls.EPUB
        if ext == "pdf":
            return cls.PDF
        raise ValueError(f"not a book file: {path}")

    def extension(self) -> str:
        """Get the file extension for the format."""
        return self.value


class FileKind(Enum):
    """Kinds of files associated with a book."""
    BOOK = "book"
    DATA = "data"


class BookInfo:
    """Information about a book in the library."""
    def __init__(self, path: Path):
        self.path = path
        self.id = path.name
        self.format = self._get_format(path)

    def _get_format(self, path: Path) -> BookFormat:
        """Detect book format by looking at files in the directory"""
        for entry in path.iterdir():
            if entry.is_file():
                try:
                    return BookFormat.from_path(entry)
                except ValueError:
                    continue
        raise ValueError(f"Valid book file not found in: {path}")

    def get_file(self, kind: FileKind) -> Path:
        """Get the file path for the specified kind."""
        ext = self.format.extension() if kind == FileKind.BOOK else "dat"
        for entry in self.path.iterdir():
            if entry.is_file() and entry.name.startswith(self.id) and \
               entry.suffix.lower() == f".{ext}":
                return entry
        return self.path / f"{self.id}.{ext}"

    def file_name(self, kind: FileKind) -> str:
        """Get just the filename for the book or data file."""
        # Return just the base name without version info for output
        if kind == FileKind.BOOK:
            return f"{self.id}.{self.format.extension()}"
        return self.get_file(kind).name


def verify(device_id: str, user_idx: str):
    """Verify the arguments are valid."""
    if len(device_id) != 36:
        raise ValueError(f"invalid device id: {device_id}")
    if not user_idx:
        raise ValueError("invalid user idx")


def library_path(user_idx: str) -> Path:
    """Get the library path for the current OS."""
    if sys.platform == "darwin":  # macOS
        home = Path(os.environ.get("HOME", "~")).expanduser()
        return home / "Library" / "Application Support" / "Ridibooks" / "library" / f"_{user_idx}"
    if sys.platform == "win32":  # Windows
        appdata = Path(os.environ.get("APPDATA", ""))
        if not appdata or not appdata.exists():
            raise ValueError("APPDATA environment variable not found")
        return appdata / "Ridibooks" / "library" / f"_{user_idx}"
    raise NotImplementedError("library_path() not implemented for this OS")


def book_infos(path: Path) -> List[BookInfo]:
    """Get BookInfo objects for all books in the library."""
    infos: List[BookInfo] = []
    if not path.exists():
        return infos

    for entry in path.iterdir():
        if entry.is_dir():
            try:
                infos.append(BookInfo(entry))
            except ValueError:
                # Skip directories that aren't book directories
                continue
    return infos


def decrypt_key(book_info: BookInfo, device_id: str, debug: bool = False) -> bytes:
    """Extract session key from encrypted .dat file."""
    data_path = book_info.get_file(FileKind.DATA)
    if not data_path.exists():
        raise FileNotFoundError(f"Missing data file: {data_path}")

    data = data_path.read_bytes()

    if debug:
        logger.debug("Data file: %s", data_path)
        logger.debug("Data file size: %d bytes", len(data))

    # Use first 16 bytes of device_id as key
    key = device_id.encode('utf-8')[:16]

    # First 16 bytes of data file is IV
    iv = data[:16]

    if debug:
        logger.debug("Key (from device_id): %s", key.hex())
        logger.debug("IV: %s", iv.hex())

    # Create AES-CBC cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data (skip first 16 bytes which is IV)
    decrypted = decryptor.update(data[16:]) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted) + unpadder.finalize()

    if debug:
        logger.debug("Decrypted plaintext size: %d bytes", len(plaintext))

    # Extract session key exactly as the 16 ASCII bytes at positions 68..84
    if len(plaintext) < 84:
        raise ValueError(f".dat plaintext too short: {len(plaintext)} bytes")

    try:
        # Range check and decode with ignore
        session_key = plaintext[68:84].decode('utf-8', errors='ignore').encode('utf-8')
        if len(session_key) != 16:
            raise ValueError("Invalid session key length")

        if debug:
            logger.debug("Session key (bytes): %s", session_key.hex())

        return session_key
    except Exception as e:
        raise ValueError(f"Failed to extract session key: {e}") from e

def _looks_like_valid_output(fmt: BookFormat, data: bytes) -> bool:
    """Check if the data looks like a valid EPUB or PDF file."""
    if fmt == BookFormat.EPUB:
        # ZIP files begin with PK\x03\x04 or sometimes PK\x05\x06 (empty zip)
        return data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"))
    if fmt == BookFormat.PDF:
        return data.startswith(b"%PDF")
    return False


def _sanitize_filename(name: str, max_len: int = 120) -> str:
    """Sanitize the filename to be safe for filesystem."""
    # Remove or replace characters invalid on Windows and most filesystems
    name = name.strip()
    # Replace forbidden characters with space
    name = re.sub(r"[\\/:*?\"<>|]", " ", name)
    # Collapse whitespace
    name = re.sub(r"\s+", " ", name).strip()
    # Trim length
    if len(name) > max_len:
        name = name[:max_len].rstrip()
    # Disallow reserved names on Windows
    reserved = {
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
        "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
        "LPT6", "LPT7", "LPT8", "LPT9"
    }
    if name.upper() in reserved:
        name = f"_{name}"
    # Avoid empty name
    return name or "untitled"


def _extract_title_epub(data: bytes) -> Optional[str]:
    """Extract book title from EPUB metadata."""
    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
            with zf.open('META-INF/container.xml') as f:
                container = ET.fromstring(f.read())

            namespaces = {'c': 'urn:oasis:names:tc:opendocument:xmlns:container'}
            rootfile = container.find('.//c:rootfile', namespaces)
            if rootfile is None:
                return None

            opf_path = rootfile.attrib.get('full-path')
            if not opf_path:
                return None

            with zf.open(opf_path) as f:
                opf = ET.fromstring(f.read())

            # Common namespaces
            ns = {
                'opf': 'http://www.idpf.org/2007/opf',
                'dc': 'http://purl.org/dc/elements/1.1/'
            }
            # Try metadata/dc:title
            title_el = opf.find('.//dc:title', ns)
            if title_el is not None and title_el.text:
                return title_el.text.strip()

            # Fallback: check without namespaces
            for el in opf.iter():
                if el.tag.lower().endswith('title') and el.text:
                    return el.text.strip()
    except (zipfile.BadZipFile, KeyError, ET.ParseError):
        pass
    return None


def _extract_title_pdf(data: bytes) -> Optional[str]:
    """Extract book title from PDF metadata."""
    try:
        try:
            import PyPDF2  # pylint: disable=import-outside-toplevel
        except ImportError:
            return None
        reader = PyPDF2.PdfReader(io.BytesIO(data))
        meta = reader.metadata
        if meta and getattr(meta, 'title', None):
            return str(meta.title).strip()
        return None
    except Exception:  # pylint: disable=broad-exception-caught
        return None


def extract_title(fmt: BookFormat, data: bytes) -> Optional[str]:
    """Extract book title from file data based on format."""
    if fmt == BookFormat.EPUB:
        return _extract_title_epub(data)
    if fmt == BookFormat.PDF:
        return _extract_title_pdf(data)
    return None


def decrypt_book(book_info: BookInfo, key: bytes, debug: bool = False) -> bytes:
    """Decrypt the book file using the decrypted key.

    Aligns with Rust reference: IV = first 16 bytes, ciphertext = rest, AES-128-CBC + PKCS7.
    If file already looks like a valid ZIP/PDF, returns as-is.
    """
    book_file_path = book_info.get_file(FileKind.BOOK)

    if not book_file_path.exists():
        raise FileNotFoundError(f"Book file not found: {book_file_path}")

    book_file = book_file_path.read_bytes()

    if debug:
        logger.debug("Book file: %s", book_file_path)
        logger.debug("Book file size: %d bytes", len(book_file))
        logger.debug("First 16 bytes: %s", book_file[:16].hex())

    # If the file already looks like a valid container, just return it as-is.
    # Some RIDI versions store plain EPUB/PDF without wrapping.
    if _looks_like_valid_output(book_info.format, book_file):
        if debug:
            logger.debug("File already looks valid; copying as-is")
        return book_file

    # Simple: use IV at start and decrypt remainder
    if len(book_file) < 16:
        raise ValueError("Book file too small to contain IV")
    iv = book_file[:16]
    ciphertext = book_file[16:]
    cipher = Cipher( algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    # PKCS7 unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(decrypted) + unpadder.finalize()
    return plaintext


def decrypt(book_info: BookInfo, device_id: str, debug: bool = False,
            output_dir: Optional[Path] = None):
    """Decrypt a book and save it to the output directory."""
    key = decrypt_key(book_info, device_id, debug)
    book_contents = decrypt_book(book_info, key, debug)

    # Determine title-based filename
    title = extract_title(book_info.format, book_contents)
    if title:
        safe = _sanitize_filename(title)
        out_name = f"{safe}.{book_info.format.extension()}"
    else:
        out_name = book_info.file_name(FileKind.BOOK)

    out_dir = output_dir or Path.cwd()
    target = out_dir / out_name

    # Avoid overwriting by appending a suffix if needed
    if target.exists():
        stem = target.stem
        suffix = target.suffix
        i = 1
        while target.exists() and i < 1000:
            target = out_dir / f"{stem} ({i}){suffix}"
            i += 1

    target.write_bytes(book_contents)
    if debug:
        logger.debug("Wrote output: %s", target)


def decrypt_with_progress(book_info: BookInfo, device_id: str, debug: bool = False,
                          output_dir: Optional[Path] = None):
    """Decrypt a book with progress indicator."""
    file_name = book_info.file_name(FileKind.BOOK)

    print(f"\r⣿ Decrypting \"{file_name}\"", end="", flush=True)

    try:
        decrypt(book_info, device_id, debug, output_dir)
        print(f"\r⣿ Decrypting \"{file_name}\" ✔︎")
        return True
    except Exception as e:  # pylint: disable=broad-exception-caught
        print(f"\r⣿ Decrypting \"{file_name}\" ✘")
        if debug:
            logger.error("Error decrypting %s: %s", book_info.id, e)
        return False
