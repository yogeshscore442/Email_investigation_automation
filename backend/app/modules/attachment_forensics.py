import os
import zipfile
import logging
from pathlib import Path
from ..config import Config
from ..utils.threat_intel import threat_intel

logger = logging.getLogger(__name__)

# Known Magic Byte signatures
MAGIC_SIGNATURES = [
    (b"\x4d\x5a", "application/x-dosexec", ".exe"), # MZ PE executable
    (b"\x50\x4b\x03\x04", "application/zip", ".zip"), # ZIP / Office OpenXML
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", ".ole"), # OLE2 (Compound File Binary)
    (b"%PDF-", "application/pdf", ".pdf"),
    (b"\x7fELF", "application/x-executable", ".elf"),
    (b"\x1f\x8b\x08", "application/gzip", ".gz"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", ".7z"),
]

SUSPICIOUS_MACRO_KEYWORDS = [
    "AutoOpen", "Document_Open", "Workbook_Open", "Auto_Open",
    "AutoExec", "Document_Close", "Workbook_BeforeClose",
    "Shell", "WScript.Shell", "CreateObject", "GetObject",
    "Powershell", "cmd.exe", "URLDownloadToFile", "XMLHTTP",
    "WinHttp.WinHttpRequest", "Environ", "CallByName", "VirtualAlloc",
    "WriteProcessMemory", "CreateRemoteThread", "Base64"
]

class AttachmentForensicsModule:
    """
    Module 5: Attachment Investigation
    Performs safe static forensics on attachments:
    - Magic byte identification and extension mismatch detection
    - SHA256 and MD5 hash calculation
    - Macro detection via olevba / OpenXML inspection
    - Dangerous script/executable extension checks
    - VirusTotal hash reputation lookup
    """

    def analyze_attachments(self, attachments_list: list) -> list:
        analyzed = []
        for att in attachments_list:
            res = self._analyze_single_attachment(att)
            analyzed.append(res)
        return analyzed

    def _analyze_single_attachment(self, att: dict) -> dict:
        filename = att.get("filename", "unknown.bin")
        raw_bytes = att.get("raw_bytes") or b""
        safe_path = att.get("safe_path", "")
        file_size = att.get("file_size", len(raw_bytes))
        reported_mime = att.get("reported_mime", "application/octet-stream")
        md5_hash = att.get("md5", "")
        sha256_hash = att.get("sha256", "")

        # If raw_bytes not present in memory, read from safe_path
        if not raw_bytes and safe_path and os.path.exists(safe_path):
            try:
                with open(safe_path, "rb") as f:
                    raw_bytes = f.read(1024 * 1024 * 10) # inspect up to 10MB
            except Exception as e:
                logger.error(f"Failed to read attachment: {e}")

        # Compute hashes if not already provided
        if raw_bytes and not sha256_hash:
            import hashlib
            sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        if raw_bytes and not md5_hash:
            import hashlib
            md5_hash = hashlib.md5(raw_bytes).hexdigest()

        # 1. File Extension & Dangerous Extension Flag
        ext = os.path.splitext(filename)[1].lower()
        is_dangerous_extension = ext in Config.DANGEROUS_EXTENSIONS

        # Double extension check: e.g. invoice.pdf.exe
        parts = filename.lower().split(".")
        if len(parts) > 2 and f".{parts[-1]}" in Config.DANGEROUS_EXTENSIONS:
            is_dangerous_extension = True

        # 2. Magic Byte Detection & Extension Mismatch
        detected_mime = "application/octet-stream"
        expected_ext = ""
        for magic, mime, mime_ext in MAGIC_SIGNATURES:
            if raw_bytes.startswith(magic):
                detected_mime = mime
                expected_ext = mime_ext
                break

        # Check for HTML/Script in text
        if detected_mime == "application/octet-stream" and raw_bytes:
            sample = raw_bytes[:512].lower()
            if b"<!doctype html" in sample or b"<html" in sample or b"<script" in sample:
                detected_mime = "text/html"
                expected_ext = ".html"
            elif b"<?xml" in sample or b"<svg" in sample:
                detected_mime = "image/svg+xml"
                expected_ext = ".svg"

        is_mismatch = False
        if expected_ext:
            if expected_ext == ".exe" and ext != ".exe":
                is_mismatch = True # Highly critical: executable masquerading as something else!
            elif expected_ext == ".zip" and ext not in [".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".jar"]:
                is_mismatch = True
            elif expected_ext == ".ole" and ext not in [".doc", ".xls", ".ppt", ".ole", ".msg"]:
                is_mismatch = True

        # 3. Macro Detection
        has_macro, macro_findings = self._detect_macros(raw_bytes, ext, safe_path)

        # 4. VirusTotal Hash Reputation Check
        vt_rep = "unknown"
        vt_malicious_votes = 0
        if sha256_hash:
            vt_res = threat_intel.check_vt_hash(sha256_hash)
            vt_rep = vt_res.get("verdict", "unknown")
            vt_malicious_votes = vt_res.get("malicious_votes", 0)

        return {
            "filename": filename,
            "file_size": file_size,
            "reported_mime": reported_mime,
            "detected_mime": detected_mime,
            "is_mismatch": is_mismatch,
            "is_dangerous_extension": is_dangerous_extension,
            "has_macro": has_macro,
            "macro_findings": macro_findings,
            "sha256": sha256_hash,
            "md5": md5_hash,
            "vt_reputation": vt_rep,
            "vt_malicious_votes": vt_malicious_votes,
            "safe_storage_path": safe_path
        }

    def _detect_macros(self, raw_bytes: bytes, ext: str, safe_path: str) -> tuple:
        """
        Inspects Office documents for VBA macros and suspicious execution routines.
        Uses oletools.olevba when available and fallback zip inspection.
        """
        findings = []
        has_macro = False

        # Fast path 1: OpenXML (.docx, .docm, .xlsx, .xlsm, .pptm) contains vbaProject.bin
        if ext in [".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx", ".zip"] or raw_bytes.startswith(b"\x50\x4b\x03\x04"):
            try:
                import io
                with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                    names = z.namelist()
                    if any("vbaProject.bin" in name for name in names):
                        has_macro = True
                        findings.append("OpenXML container embeds 'vbaProject.bin' compiled macro payload")
            except Exception:
                pass

        # Fast path 2: Use olevba from oletools
        if safe_path and os.path.exists(safe_path) and (has_macro or ext in [".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm"]):
            try:
                from oletools.olevba import VBA_Parser
                vb_parser = VBA_Parser(safe_path)
                if vb_parser.detect_vba_macros():
                    has_macro = True
                    for (filename, stream_path, vba_filename, vba_code) in vb_parser.extract_macros():
                        for keyword in SUSPICIOUS_MACRO_KEYWORDS:
                            if keyword.lower() in vba_code.lower():
                                findings.append(f"Suspicious VBA keyword detected: '{keyword}' in macro module '{vba_filename}'")
                vb_parser.close()
            except Exception as e:
                logger.debug(f"olevba analysis encountered error: {e}")

        # Fallback keyword scan on raw bytes
        if ext in [".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".doc", ".xls"] or has_macro or not findings:
            for kw in ["AutoOpen", "Document_Open", "Workbook_Open", "Shell", "powershell", "CreateObject", "wscript"]:
                if kw.encode() in raw_bytes or kw.lower().encode() in raw_bytes:
                    has_macro = True
                    hit_msg = f"Heuristic byte scan identified macro execution string: '{kw}'"
                    if hit_msg not in findings:
                        findings.append(hit_msg)

        return has_macro, findings

attachment_forensics = AttachmentForensicsModule()

