import re
from bs4 import BeautifulSoup
import bleach
from bleach.css_sanitizer import CSSSanitizer

# Allowed safe tags for previewing sanitized email HTML without active content
SAFE_TAGS = [
    'p', 'div', 'span', 'b', 'strong', 'i', 'em', 'u', 'table', 'tr', 'td', 'th',
    'tbody', 'thead', 'tfoot', 'ul', 'ol', 'li', 'br', 'hr', 'h1', 'h2', 'h3',
    'h4', 'h5', 'h6', 'blockquote', 'pre', 'code', 'font'
]

SAFE_ATTRIBUTES = {
    '*': ['style', 'class', 'align', 'valign', 'width', 'height', 'color'],
    'font': ['face', 'size', 'color'],
    'table': ['border', 'cellpadding', 'cellspacing', 'width', 'bgcolor'],
    'td': ['colspan', 'rowspan', 'width', 'align', 'valign'],
    'th': ['colspan', 'rowspan', 'width', 'align', 'valign']
}

def sanitize_email_html(html_content: str) -> dict:
    """
    Sanitizes raw email HTML for safe SOC display and detects embedded threats:
    - Neutralizes scripts, frames, objects
    - Defangs external image web beacons to prevent analyst de-anonymization
    - Dissects forms targeting credential harvesting
    - Returns sanitized HTML and structural security findings
    """
    if not html_content:
        return {
            "sanitized_html": "<p><em>No HTML body content present.</em></p>",
            "detected_forms": [],
            "removed_scripts": 0,
            "has_hidden_elements": False,
            "has_web_beacons": False
        }

    soup = BeautifulSoup(html_content, "html.parser")
    
    # 1. Detect and inspect forms (Potential Credential Harvesting)
    detected_forms = []
    forms = soup.find_all("form")
    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = []
        for inp in form.find_all(["input", "select", "textarea"]):
            inputs.append({
                "type": inp.get("type", "text"),
                "name": inp.get("name", ""),
                "id": inp.get("id", "")
            })
        detected_forms.append({
            "action": action,
            "method": method,
            "input_count": len(inputs),
            "inputs": inputs,
            "has_password_field": any(i["type"] == "password" for i in inputs)
        })

    # 2. Count & neutralize scripts & active elements
    scripts = soup.find_all("script")
    removed_scripts_count = len(scripts)
    for s in scripts:
        s.decompose()  # Purge tag and its script text completely

    # Also decompose dangerous objects/embeds/iframes
    for el in soup.find_all(["iframe", "object", "embed", "applet", "meta"]):
        el.decompose()
    
    # 3. Detect 1x1 tracking pixels / web beacons
    has_web_beacons = False
    images = soup.find_all("img")
    for img in images:
        w = str(img.get("width", "")).strip()
        h = str(img.get("height", "")).strip()
        src = img.get("src", "").strip()
        src_lower = src.lower()
        if (w in ["0", "1"] and h in ["0", "1"]) or "track" in src_lower or "beacon" in src_lower:
            has_web_beacons = True
            
        # Neutralize image src for analyst privacy: prefix with safe placeholder or disable auto-load
        if src_lower.startswith(("http://", "https://", "//")):
            img["data-original-src"] = src
            img["src"] = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16'><rect width='100%' height='100%' fill='%23334155'/></svg>"
            img["title"] = f"External Image Neutralized [Defanged: {src}]"
            img["alt"] = "[External Image Neutralized]"

    # 4. Detect hidden text/elements used by phishers (e.g. display:none, font-size:0)
    has_hidden_elements = False
    for el in soup.find_all(True):
        style = el.get("style", "").lower()
        if "display:none" in style or "visibility:hidden" in style or "font-size:0" in style or "color:white" in style:
            has_hidden_elements = True
            break

    # 5. Defang all anchors so analysts cannot accidentally click them
    anchors = soup.find_all("a")
    for a in anchors:
        raw_href = a.get("href", "")
        if raw_href:
            # Defang dangerous javascript: or data: pseudo-protocols
            safe_target = raw_href
            if raw_href.lower().startswith("javascript:"):
                safe_target = "blocked-script-protocol:" + raw_href[11:]
            elif raw_href.lower().startswith("data:"):
                safe_target = "blocked-data-protocol:" + raw_href[5:]

            a["data-original-href"] = safe_target
            a["href"] = "#"
            a["title"] = f"Original Target: {safe_target}"
            a["target"] = "_self"
            a["class"] = (a.get("class", []) or []) + ["defanged-link"]

    # 6. Apply bleach whitelist with CSSSanitizer
    css_sanitizer = CSSSanitizer(allowed_css_properties=[
        'color', 'background-color', 'font-family', 'font-size', 'font-weight',
        'text-align', 'padding', 'margin', 'border', 'width', 'height', 'max-width'
    ])

    cleaned = bleach.clean(
        str(soup),
        tags=SAFE_TAGS + ['a', 'img'],
        attributes={
            **SAFE_ATTRIBUTES,
            'a': ['href', 'title', 'data-original-href', 'class', 'target'],
            'img': ['src', 'alt', 'title', 'data-original-src', 'width', 'height', 'style']
        },
        css_sanitizer=css_sanitizer,
        strip=True
    )

    return {
        "sanitized_html": cleaned,
        "detected_forms": detected_forms,
        "removed_scripts": removed_scripts_count,
        "has_hidden_elements": has_hidden_elements,
        "has_web_beacons": has_web_beacons
    }

