# app.py
import base64
import os
import re
import requests
import streamlit as st

KG_ENDPOINT = "https://kgsearch.googleapis.com/v1/entities:search"
MID_RE = re.compile(r"^/m/[0-9a-z_]+$")

# ========== utils: base64url + varint + token ==========
def b64url_nopad_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def varint_encode(n: int) -> bytes:
    out = bytearray()
    while True:
        to_write = n & 0x7F
        n >>= 7
        if n:
            out.append(to_write | 0x80)
        else:
            out.append(to_write)
            break
    return bytes(out)

def encode_profile_token_from_mid(mid: str) -> str:
    if not MID_RE.match(mid):
        raise ValueError("MID inválido (esperado algo como '/m/07k2d').")
    mb = mid.encode("utf-8")
    protobuf = bytes([0x0A]) + varint_encode(len(mb)) + mb  # field 1, length-delimited
    return b64url_nopad_encode(protobuf)

def build_profile_url(token: str) -> str:
    return f"https://profile.google.com/cp/{token}"

# ========== KG Search ==========
def extract_mid_from_id(id_value: str) -> str | None:
    """
    El @id de KG suele venir como 'kg:/m/079l8w' o 'https://kg.google.com/m/079l8w'
    o 'g:/...' / '/g/...'. Acá nos quedamos sólo con '/m/...'.
    """
    # Normalizar separadores
    parts = id_value.split("/")
    # Buscar el segmento 'm' y devolver '/m/<resto>'
    for i, p in enumerate(parts):
        if p == "m" and i + 1 < len(parts):
            mid = "/m/" + parts[i + 1]
            return mid if MID_RE.match(mid) else None
        if p.startswith("m") and p != "m":  # por si viene 'm:079l8w' (raro)
            candidate = "/m/" + p.split(":")[-1]
            return candidate if MID_RE.match(candidate) else None
    # A veces viene como 'kg:/m/079l8w' completo en una sola cadena:
    m = re.search(r"(/m/[0-9a-z_]+)", id_value)
    if m:
        mid = m.group(1)
        return mid if MID_RE.match(mid) else None
    return None

@st.cache_data(show_spinner=False, ttl=1800)
def kg_search(query: str, api_key: str, lang: str = "es", limit: int = 10):
    params = {
        "query": query,
        "key": api_key,
        "limit": limit,
        "languages": lang,
    }
    r = requests.get(KG_ENDPOINT, params=params, timeout=20)
    r.raise_for_status()
    return r.json()

# ========== UI ==========
st.set_page_config(page_title="KG → MID → cp/ URL", page_icon="🧩", layout="centered")
st.title("🧩 Google KG → MID → profile.google.com/cp/…")
st.caption("Ingresa un nombre, obtené el MID con la Knowledge Graph API y generá la URL de profile.")

with st.sidebar:
    st.header("🔐 API Key")
    default_key = st.secrets.get("KG_API_KEY", "")
    api_key = st.text_input("Google KG API key", value=default_key, type="password")
    st.markdown(
        "- Crea una API key en Google Cloud y habilita **Knowledge Graph Search API**.\n"
        "- También podés definir `KG_API_KEY` en *Secrets* de Streamlit."
    )
    st.header("🔧 Opciones")
    lang = st.selectbox("Idioma", ["es", "en", "pt", "fr", "de"], index=0)
    limit = st.slider("Resultados", 1, 20, 10)

tab1, tab2 = st.tabs(["🔎 Buscar por nombre", "🆔 Ya tengo el MID"])

with tab1:
    q = st.text_input("Nombre de la entidad (ej.: clarin, infobae, the new york times)")
    if st.button("Buscar en Google KG", disabled=not q.strip()):
        if not api_key:
            st.error("Ingresá tu API key primero.")
        else:
            try:
                data = kg_search(q.strip(), api_key, lang=lang, limit=limit)
                items = data.get("itemListElement", [])
                if not items:
                    st.warning("Sin resultados en KG.")
                else:
                    # Armar opciones (label, description, @type)
                    options = []
                    for it in items:
                        res = it.get("result", {})
                        name = res.get("name") or ""
                        desc = res.get("description") or ""
                        types = ", ".join(res.get("@type", [])) if isinstance(res.get("@type", []), list) else (res.get("@type") or "")
                        kid = res.get("@id") or ""
                        score = it.get("resultScore")
                        options.append({
                            "name": name,
                            "desc": desc,
                            "types": types,
                            "kid": kid,
                            "score": score,
                        })
                    def fmt(o):
                        base = f"{o['name']} — {o['desc']} [{o['types']}]"
                        if o["score"] is not None:
                            base += f"  (score: {o['score']:.2f})"
                        return base

                    sel = st.selectbox("Elegí la entidad correcta:", options, format_func=fmt)
                    if sel:
                        mid = extract_mid_from_id(sel["kid"]) if sel["kid"] else None
                        if not mid:
                            st.error(f"No pude extraer un MID '/m/...' del @id: {sel['kid']!r}")
                        else:
                            try:
                                token = encode_profile_token_from_mid(mid)
                                url = build_profile_url(token)
                                st.success("¡Listo!")
                                st.write("**Nombre:**", sel["name"])
                                st.write("**@id (KG):**", f"`{sel['kid']}`")
                                st.write("**MID:**", f"`{mid}`")
                                st.write("
