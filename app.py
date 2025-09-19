# app.py
import base64
import re
import requests
import streamlit as st

WIKIDATA_SEARCH = "https://www.wikidata.org/w/api.php"
WIKIDATA_ENTITY = "https://www.wikidata.org/wiki/Special:EntityData/{qid}.json"
MID_RE = re.compile(r"^/m/[0-9a-z_]+$")

# ========== Utils: base64url & protobuf length (varint) ==========

def b64url_nopad_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def varint_encode(n: int) -> bytes:
    """Varint (protobuf) para longitudes >= 128 también."""
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
    mid_b = mid.encode("utf-8")
    # Mensaje protobuf mínimo: field #1 (wire type 2) -> tag 0x0A, luego len (varint), luego bytes
    protobuf = bytes([0x0A]) + varint_encode(len(mid_b)) + mid_b
    return b64url_nopad_encode(protobuf)

def build_profile_url(token: str) -> str:
    return f"https://profile.google.com/cp/{token}"

# ========== Wikidata helpers ==========

@st.cache_data(show_spinner=False, ttl=3600)
def wikidata_search(query: str, language: str = "es", limit: int = 10):
    params = {
        "action": "wbsearchentities",
        "search": query,
        "language": language,
        "uselang": language,
        "format": "json",
        "limit": limit,
    }
    r = requests.get(WIKIDATA_SEARCH, params=params, timeout=20)
    r.raise_for_status()
    return r.json().get("search", [])

@st.cache_data(show_spinner=False, ttl=3600)
def wikidata_get_mid(qid: str) -> str | None:
    r = requests.get(WIKIDATA_ENTITY.format(qid=qid), timeout=20)
    r.raise_for_status()
    ent = r.json()["entities"][qid]
    claims = ent.get("claims", {})
    p646 = claims.get("P646")
    if not p646:
        return None
    # tomar el primer valor de P646
    return p646[0]["mainsnak"]["datavalue"]["value"]

# ========== UI ==========

st.set_page_config(page_title="Google Profile cp/ token builder", page_icon="🧩", layout="centered")
st.title("🧩 Google Profile cp/ token builder")
st.caption("De nombre → MID (Wikidata P646) → token → URL `profile.google.com/cp/…`")

with st.sidebar:
    st.header("🔧 Opciones")
    lang = st.selectbox("Idioma de búsqueda en Wikidata", ["es", "en", "pt", "fr", "de"], index=0)
    limit = st.slider("Resultados a listar", 1, 20, 10)

tab1, tab2 = st.tabs(["🔎 Buscar por nombre", "🆔 Ya tengo el MID"])

with tab1:
    q = st.text_input("Nombre de la entidad (ej: clarin, the new york times, infobae)", "")
    if st.button("Buscar en Wikidata", disabled=not q.strip()):
        try:
            results = wikidata_search(q.strip(), language=lang, limit=limit)
            if not results:
                st.warning("No se encontraron resultados.")
            else:
                # Render lista y permitir elegir uno
                options = []
                for it in results:
                    label = it.get("label") or ""
                    desc = it.get("description") or ""
                    qid = it["id"]
                    options.append((qid, f"{label} — {desc} ({qid})"))

                sel = st.selectbox("Elegí la entidad correcta:", options, format_func=lambda x: x[1])
                if sel:
                    qid = sel[0]
                    with st.spinner(f"Buscando Freebase ID (P646) para {qid}…"):
                        mid = wikidata_get_mid(qid)
                    if not mid:
                        st.error("La entidad seleccionada no tiene Freebase ID (P646). Probá con otra.")
                    else:
                        try:
                            token = encode_profile_token_from_mid(mid)
                            url = build_profile_url(token)
                            st.success("¡Listo!")
                            st.write("**QID:**", qid)
                            st.write("**MID:**", f"`{mid}`")
                            st.write("**Token (base64url):**")
                            st.code(token, language="text")
                            st.link_button("Abrir URL", url)
                            st.text_input("Copiar URL", url)
                        except Exception as e:
                            st.exception(e)
        except requests.RequestException as e:
            st.error("Error de red al consultar Wikidata.")
            st.exception(e)

with tab2:
    mid_input = st.text_input("Pegá un MID directamente (ej: /m/079l8w)", "")
    if st.button("Generar URL desde MID", disabled=not mid_input.strip()):
        try:
            token = encode_profile_token_from_mid(mid_input.strip())
            url = build_profile_url(token)
            st.success("¡Listo!")
            st.write("**MID:**", f"`{mid_input.strip()}`")
            st.write("**Token (base64url):**")
            st.code(token, language="text")
            st.link_button("Abrir URL", url)
            st.text_input("Copiar URL", url)
        except Exception as e:
            st.exception(e)

st.divider()
with st.expander("❓Notas rápidas"):
    st.markdown(
        """
- La app busca en Wikidata y usa la **propiedad P646 (Freebase ID)** como MID.
- El token se arma con un **mensaje protobuf mínimo**: `0x0A` (campo 1, length-delimited) + `len(varint)` + bytes del MID.  
- Se codifica en **base64 URL-safe sin padding** y se pega en `https://profile.google.com/cp/<token>`.
- Si necesitás precisión total en entidades con nombre ambiguo, elegí la correcta en la lista (mirá la descripción/QID).
        """
    )
