# app.py
import re
import base64
import requests
import streamlit as st
from urllib.parse import urlparse

KG_ENDPOINT = "https://kgsearch.googleapis.com/v1/entities:search"
ID_RE = re.compile(r"^/(m|g)/[0-9a-z_]+$")

# ========== Domain normalization ==========
def normalize_host(site_url: str) -> str:
    """
    Normalize a site URL into a lowercase host without 'www.'.
    """
    u = site_url.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    host = urlparse(u).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host

def host_of(url: str | None) -> str | None:
    """
    Extract host (without 'www.') from a URL-like string.
    Returns None on parse errors.
    """
    if not url:
        return None
    try:
        u = url
        if not u.startswith(("http://", "https://")):
            u = "https://" + u
        h = urlparse(u).netloc.lower()
        if h.startswith("www."):
            h = h[4:]
        return h
    except Exception:
        return None

# ========== cp/ token (protobuf + base64url) ==========
def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def cp_token_from_kgid(kgid: str) -> str:
    """
    Build the cp/ token by wrapping the KG id in a protobuf (field #1, length-delimited)
    and encoding it with base64 URL-safe without padding.
    """
    if not ID_RE.match(kgid):
        raise ValueError("Invalid ID; expected '/m/...' or '/g/...'.")
    payload = kgid.encode("utf-8")
    proto = bytes([0x0A]) + _varint(len(payload)) + payload  # field #1, length-delimited
    return _b64url_nopad(proto)

def cp_url_from_kgid(kgid: str) -> str:
    return f"https://profile.google.com/cp/{cp_token_from_kgid(kgid)}"

# ========== Knowledge Graph helpers ==========
def extract_id_from_result(result: dict) -> str | None:
    """
    Extract a '/m/...' or '/g/...' id from a KG result payload.
    """
    kg_id = result.get("@id") or result.get("id")
    if not kg_id:
        return None
    if kg_id.startswith("kg:"):
        kg_id = kg_id[3:]
    return kg_id if ID_RE.match(kg_id) else None

@st.cache_data(show_spinner=False, ttl=1800)
def kg_search(query: str, api_key: str, languages: str, limit: int, types: list[str] | None):
    """
    Query the Google Knowledge Graph Search API with an optional list of schema.org types.
    """
    base_params = {"query": query, "key": api_key, "limit": limit, "languages": languages}
    if types:
        items = []
        for t in types:
            params = dict(base_params)
            params["types"] = t
            r = requests.get(KG_ENDPOINT, params=params, timeout=20)
            r.raise_for_status()
            item
