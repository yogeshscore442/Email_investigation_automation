import os
import uuid
import email
from email import policy
from email.parser import BytesParser, HeaderParser
import hashlib
import re
from pathlib import Path
from bs4 import BeautifulSoup
from werkzeug.utils import secure_filename
from ..config import Config

class EmailParserModule:
    """
    Module 1: Email Collection and Parsing
    Parses .eml and .msg files, extracts headers, bodies, attachments, and URLs.
    Preserves original evidence securely.
    """
    
    def parse_eml_bytes(self, raw_bytes: bytes, original_filename: str = "evidence.eml") -> dict:
        """Parses raw EML bytes into structured data."""
        # Save raw evidence
        evidence_id = str(uuid.uuid4())
        safe_fn = f"{evidence_id}_{secure_filename(original_filename) or 'evidence.eml'}"
        evidence_path = Config.STORAGE_DIR / safe_fn
        with open(evidence_path, "wb") as f:
            f.write(raw_bytes)

        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        return self._extract_message_data(msg, str(evidence_path))

    def parse_msg_file(self, file_path: str) -> dict:
        """Parses Outlook .msg file using extract_msg library."""
        try:
            import extract_msg
            msg = extract_msg.Message(file_path)
            
            headers_dict = {}
            if msg.header:
                for line in str(msg.header).splitlines():
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers_dict[k.strip()] = v.strip()
            
            # Extract attachments
            attachments = []
            for att in msg.attachments:
                raw_name = att.shortFilename or att.longFilename or "attachment.bin"
                att_name = secure_filename(raw_name) or f"attachment_{uuid.uuid4().hex[:8]}.bin"
                att_data = att.data
                if att_data:
                    md5_hash = hashlib.md5(att_data).hexdigest()
                    sha256_hash = hashlib.sha256(att_data).hexdigest()
                    att_id = str(uuid.uuid4())
                    att_path = (Config.STORAGE_DIR / f"{att_id}_{att_name}").resolve()
                    if not str(att_path).startswith(str(Config.STORAGE_DIR.resolve())):
                        att_path = Config.STORAGE_DIR / f"{att_id}_sanitized_attachment.bin"
                    with open(att_path, "wb") as af:
                        af.write(att_data)
                    attachments.append({
                        "filename": att_name,
                        "file_size": len(att_data),
                        "reported_mime": att.mimetype or "application/octet-stream",
                        "md5": md5_hash,
                        "sha256": sha256_hash,
                        "safe_path": str(att_path),
                        "raw_bytes": att_data
                    })

            body_plain = msg.body or ""
            body_html = msg.htmlBody or ""
            if isinstance(body_html, bytes):
                try:
                    body_html = body_html.decode("utf-8", errors="replace")
                except Exception:
                    body_html = ""

            return {
                "evidence_path": file_path,
                "subject": msg.subject or "[No Subject]",
                "sender": msg.sender or "",
                "recipient": msg.to or "",
                "cc": msg.cc or "",
                "bcc": msg.bcc or "",
                "reply_to": "",
                "date": str(msg.date or ""),
                "message_id": headers_dict.get("Message-ID", headers_dict.get("message-id", "")),
                "headers": [{"name": k, "value": v} for k, v in headers_dict.items()],
                "body_plain": body_plain,
                "body_html": body_html,
                "attachments": attachments,
                "raw_headers_text": str(msg.header or "")
            }
        except Exception as e:
            raise ValueError(f"Failed to parse Outlook .msg file: {str(e)}")

    def parse_raw_text(self, raw_headers_text: str, raw_body_text: str = "") -> dict:
        """Parses raw pasted headers and body text."""
        parser = HeaderParser()
        headers = parser.parsestr(raw_headers_text)
        
        headers_list = []
        for k, v in headers.items():
            headers_list.append({"name": k, "value": v})
            
        evidence_id = str(uuid.uuid4())
        evidence_path = Config.STORAGE_DIR / f"{evidence_id}_pasted_evidence.txt"
        with open(evidence_path, "w", encoding="utf-8") as f:
            f.write(f"--- HEADERS ---\n{raw_headers_text}\n\n--- BODY ---\n{raw_body_text}")

        # Check if body contains HTML tags
        is_html = bool(re.search(r'<(html|body|div|p|br|table|a)\b', raw_body_text, re.IGNORECASE))
        body_plain = ""
        body_html = ""
        if is_html:
            body_html = raw_body_text
            soup = BeautifulSoup(raw_body_text, "html.parser")
            body_plain = soup.get_text(separator="\n").strip()
        else:
            body_plain = raw_body_text

        return {
            "evidence_path": str(evidence_path),
            "subject": headers.get("Subject", "[No Subject]"),
            "sender": headers.get("From", ""),
            "recipient": headers.get("To", ""),
            "cc": headers.get("Cc", ""),
            "bcc": headers.get("Bcc", ""),
            "reply_to": headers.get("Reply-To", ""),
            "date": headers.get("Date", ""),
            "message_id": headers.get("Message-ID", headers.get("Message-Id", "")),
            "headers": headers_list,
            "body_plain": body_plain,
            "body_html": body_html,
            "attachments": [],
            "raw_headers_text": raw_headers_text
        }

    def _extract_message_data(self, msg: email.message.EmailMessage, evidence_path: str) -> dict:
        """Extracts structured fields from parsed email.message.EmailMessage."""
        headers_list = []
        for k, v in msg.items():
            headers_list.append({"name": k, "value": str(v)})

        subject = str(msg.get("Subject", "[No Subject]"))
        sender = str(msg.get("From", ""))
        recipient = str(msg.get("To", ""))
        cc = str(msg.get("Cc", ""))
        bcc = str(msg.get("Bcc", ""))
        reply_to = str(msg.get("Reply-To", ""))
        date = str(msg.get("Date", ""))
        message_id = str(msg.get("Message-ID", msg.get("Message-Id", "")))

        body_plain = ""
        body_html = ""
        attachments = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()

                # If attachment
                if filename or "attachment" in content_disposition:
                    att_filename = secure_filename(filename or "") or f"attachment_{uuid.uuid4().hex[:8]}.bin"
                    payload = part.get_payload(decode=True) or b""
                    md5_hash = hashlib.md5(payload).hexdigest()
                    sha256_hash = hashlib.sha256(payload).hexdigest()
                    
                    att_id = str(uuid.uuid4())
                    att_path = (Config.STORAGE_DIR / f"{att_id}_{att_filename}").resolve()
                    if not str(att_path).startswith(str(Config.STORAGE_DIR.resolve())):
                        att_path = Config.STORAGE_DIR / f"{att_id}_sanitized_attachment.bin"
                    with open(att_path, "wb") as af:
                        af.write(payload)

                    attachments.append({
                        "filename": att_filename,
                        "file_size": len(payload),
                        "reported_mime": content_type,
                        "md5": md5_hash,
                        "sha256": sha256_hash,
                        "safe_path": str(att_path),
                        "raw_bytes": payload
                    })
                elif content_type == "text/plain" and not body_plain:
                    try:
                        body_plain = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        body_plain = payload.decode("utf-8", errors="replace") if payload else ""
                elif content_type == "text/html" and not body_html:
                    try:
                        body_html = part.get_content()
                    except Exception:
                        payload = part.get_payload(decode=True)
                        body_html = payload.decode("utf-8", errors="replace") if payload else ""
        else:
            content_type = msg.get_content_type()
            try:
                content = msg.get_content()
            except Exception:
                payload = msg.get_payload(decode=True)
                content = payload.decode("utf-8", errors="replace") if payload else ""

            if content_type == "text/html":
                body_html = content
                soup = BeautifulSoup(content, "html.parser")
                body_plain = soup.get_text(separator="\n").strip()
            else:
                body_plain = content

        # If we have HTML but no plain text, extract plain text from HTML
        if body_html and not body_plain:
            soup = BeautifulSoup(body_html, "html.parser")
            body_plain = soup.get_text(separator="\n").strip()

        return {
            "evidence_path": evidence_path,
            "subject": subject,
            "sender": sender,
            "recipient": recipient,
            "cc": cc,
            "bcc": bcc,
            "reply_to": reply_to,
            "date": date,
            "message_id": message_id,
            "headers": headers_list,
            "body_plain": body_plain,
            "body_html": body_html,
            "attachments": attachments,
            "raw_headers_text": "\n".join(f"{h['name']}: {h['value']}" for h in headers_list)
        }

email_parser = EmailParserModule()

