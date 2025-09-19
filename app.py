# app.py
import base64
import re
import requests
import streamlit as st

KG_ENDPOINT = "https://kgsearch.googleapis.com/v1/entities:search"
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
    protobuf = bytes([0x0A]) + varint_encode(len(mid_b)) + mid_b  # field #1 (len-delimited)
    return b64url_nopad_encode(protobuf)

def build_profile_url(token: str) -> str:
    return f"https://profile.google.com/cp/{token}"

# ========== Knowledge Graph helpers ==========

def extract_mid_from_result(result: dict) -> str | None:
    """
    Intenta obtener el MID de un item del KG Search.
    Normalmente viene en result['@id'] = 'kg:/m/XXXX'; si está, se le quita 'kg:'.
    """
    kg_id = result.get("@id") or result.get("id")
    if not kg_id:
        return None
    # Quitar prefijo 'kg:' si existe
    if kg_id.startswith("kg:"):
        kg_id = kg_id[3:]
    return kg_id if MID_RE.match(kg_id) else None

@st.cache_data(show_spinner=False, ttl=1800)
def kg_search(query: str, api_key: str, languages: str = "es", types: list[str] | None = None, limit: int = 10):
    params = {
        "query": query,
        "key": api_key,
        "limit": limit,
        "languages": languages,
    }
    if types:
        # El parámetro 'types' acepta una sola cadena; si pasamos varias, iteramos nosotros
        all_items = []
        for t in types:
            p = dict(params)
            p["types"] = t
            r = requests.get(KG_ENDPOINT, params=p, timeout=20)
            r.raise_for_status()
            all_items.extend(r.json().get("itemListElement", []))
        return all_items
    else:
        r = requests.get(KG_ENDPOINT, params=params, timeout=20)
        r.raise_for_status()
        return r.json().get("itemListElement", [])

# ========== UI ==========

st.set_page_config(page_title="Google Profile cp/ token builder (KG API)", page_icon="🧩", layout="centered")
st.title("🧩 Google Profile cp/ token builder — Knowledge Graph API")
st.caption("De nombre → MID (KG) → token → URL `profile.google.com/cp/…`")

with st.sidebar:
    st.header("🔐 Credenciales")
    default_key = st.secrets.get("GOOGLE_API_KEY", "")
    api_key = st.text_input("Google API Key", value=default_key, type="password", help="Colocá tu API key de Google (KG Search API activada).")
    st.header("🔧 Opciones")
    lang = st.selectbox("Idioma (languages)", ["es", "en", "pt", "fr", "de"], index=0)
    limit = st.slider("Resultados a listar", 1, 20, 10)
    type_hint = st.multiselect(
        "Types (opcional, ayuda a filtrar)",
        [
            "Organization", "Person", "Place", "Book", "Movie", "MusicGroup",
            "Corporation", "Newspaper", "TVSeries", "SportsTeam", "Brand"
        ],
        default=["Organization"],
        help="El KG usa tipos de schema.org; 'Organization' suele funcionar bien para medios."
    )

tab1, tab2 = st.tabs(["🔎 Buscar por nombre (KG)", "🆔 Ya tengo el MID"])

with tab1:
    q = st.text_input("Nombre de la entidad", placeholder="Ej: clarin, the new york times, infobae")
    run = st.button("Buscar en Knowledge Graph", disabled=(not q.strip() or not api_key.strip()))
    if run:
        if not api_key.strip():
            st.error("Falta la API key.")
        else:
            try:
                with st.spinner("Buscando en Google Knowledge Graph…"):
                    items = kg_search(q.strip(), api_key=api_key.strip(), languages=lang, types=type_hint or None, limit=limit)
                if not items:
                    st.warning("Sin resultados del KG para esa búsqueda.")
                else:
                    # Preparar opciones
                    options = []
                    for it in items:
                        res = it.get("result", {})
                        name = res.get("name") or ""
                        desc = res.get("description") or ""
                        mid = extract_mid_from_result(res)
                        types_str = ", ".join(res.get("@type", []))
                        score = it.get("resultScore")
                        label = f"{name} — {desc} — [{types_str}] (score={score})"
                        options.append((res, mid, label))

                    # Mostrar y elegir
                    valid_options = [o for o in options if o[1] is not None]
                    if not valid_options:
                        st.error("Se encontraron resultados pero ninguno trae MID válido en @id (kg:/m/…). Probá con otro 'types' o término.")
                    else:
                        sel = st.selectbox("Elegí la entidad correcta:", valid_options, format_func=lambda x: x[2])
                        if sel:
                            res, mid, _ = sel
                            try:
                                token = encode_profile_token_from_mid(mid)
                                url = build_profile_url(token)
                                st.success("¡Listo!")
                                st.write("**Nombre:**", res.get("name", ""))
                                st.write("**Descripción:**", res.get("description", ""))
                                st.write("**Tipos:**", ", ".join(res.get("@type", [])))
                                st.write("**MID:**", f"`{mid}`")
                                st.write("**Token (base64url):**")
                                st.code(token, language="text")
                                st.link_button("Abrir URL", url)
                                st.text_input("Copiar URL", url)
                            except Exception as e:
                                st.exception(e)
            except requests.HTTPError as e:
                # Mensaje más claro si es 4xx por API key / cuotas
                st.error("Error HTTP consultando el KG. ¿API Key correcta y KG Search API habilitada?")
                st.exception(e)
            except requests.RequestException as e:
                st.error("Error de red consultando el KG.")
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
- **Knowledge Graph Search API** devuelve `result["@id"]` con prefijo `kg:` (ej. `kg:/m/07k2d`):
  extraemos el **MID** como `/m/07k2d`.
- El token se arma con un **mensaje protobuf mínimo**: `0x0A` (campo 1, length-delimited) + `len(varint)` + bytes del MID.
- Se codifica en **base64 URL-safe sin padding** y se pega en `https://profile.google.com/cp/<token>`.
- Podés filtrar por `types` (schema.org) para afinar resultados (p. ej., `Organization` o `Newspaper`).
        """
    )
