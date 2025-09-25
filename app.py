# app.py
import re
import base64
import requests
import streamlit as st
from urllib.parse import urlparse

KG_ENDPOINT = "https://kgsearch.googleapis.com/v1/entities:search"
ID_RE = re.compile(r"^/(m|g)/[0-9a-z_]+$")

# ========== Normalización de dominio ==========
def normalize_host(site_url: str) -> str:
    u = site_url.strip()
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    host = urlparse(u).netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    return host

def host_of(url: str | None) -> str | None:
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
    if not ID_RE.match(kgid):
        raise ValueError("ID inválido; espero '/m/...' o '/g/...'.")
    payload = kgid.encode("utf-8")
    proto = bytes([0x0A]) + _varint(len(payload)) + payload  # field #1, length-delimited
    return _b64url_nopad(proto)

def cp_url_from_kgid(kgid: str) -> str:
    return f"https://profile.google.com/cp/{cp_token_from_kgid(kgid)}"

# ========== Knowledge Graph helpers ==========
def extract_id_from_result(result: dict) -> str | None:
    kg_id = result.get("@id") or result.get("id")
    if not kg_id:
        return None
    if kg_id.startswith("kg:"):
        kg_id = kg_id[3:]
    return kg_id if ID_RE.match(kg_id) else None

@st.cache_data(show_spinner=False, ttl=1800)
def kg_search(query: str, api_key: str, languages: str, limit: int, types: list[str] | None):
    base_params = {"query": query, "key": api_key, "limit": limit, "languages": languages}
    if types:
        items = []
        for t in types:
            params = dict(base_params)
            params["types"] = t
            r = requests.get(KG_ENDPOINT, params=params, timeout=20)
            r.raise_for_status()
            items.extend(r.json().get("itemListElement", []))
        return items
    else:
        r = requests.get(KG_ENDPOINT, params=base_params, timeout=20)
        r.raise_for_status()
        return r.json().get("itemListElement", [])

def choose_best_result(items: list[dict], target_host: str):
    brand_hint = target_host.split(".")[0]
    scored = []
    for it in items:
        res = it.get("result", {}) or {}
        kgid = extract_id_from_result(res)
        if not kgid:
            continue
        score = 0.0
        # (1) dominio en result.url
        res_url_host = host_of(res.get("url"))
        if res_url_host == target_host:
            score += 100.0
        # (2) dominio en sameAs
        same_as = res.get("sameAs") or []
        if isinstance(same_as, str):
            same_as = [same_as]
        for s in same_as:
            if host_of(s) == target_host:
                score += 40.0
                break
        # (3) nombre contiene marca/dom
        name = (res.get("name") or "").lower()
        if brand_hint and brand_hint in name:
            score += 5.0
        # (4) puntaje nativo
        rs = it.get("resultScore") or 0.0
        score += float(rs)
        scored.append((score, res, kgid))
    if not scored:
        return None
    scored.sort(key=lambda x: x[0], reverse=True)
    _, res, kgid = scored[0]
    return res, kgid

# ========== UI ==========
st.set_page_config(page_title="URL → (/g|/m) → Google Profile cp/", page_icon="🧩", layout="centered")
st.title("🧩 De URL del sitio → ID `/g` o `/m` → `profile.google.com/cp/…`")

with st.sidebar:
    
    api_key = st.secrets.get("GOOGLE_API_KEY", "")
    
    st.header("🔧 Opciones")
    lang = st.selectbox("Idioma (languages)", ["es", "en", "pt", "fr", "de"], index=0)
    limit = st.slider("Resultados por tipo", 1, 20, 10)
    types = st.multiselect(
        "Types (schema.org, recomendados para medios)",
        ["NewsMediaOrganization","Organization","Corporation","Brand","WebSite","Person"],
        default=["NewsMediaOrganization","Organization","Corporation","Brand"],
        help="Probá sumar 'WebSite' si no aparece nada."
    )

site_input = st.text_input("Pegá la URL del sitio (ej: https://www.clarin.com/)", "")

if st.button("Buscar ID en Knowledge Graph", disabled=(not site_input.strip() or not api_key.strip())):
    if not api_key.strip():
        st.error("Falta la API key.")
    else:
        try:
            target_host = normalize_host(site_input)
            with st.spinner(f"Buscando entidad del KG para: {target_host} …"):
                queries = [target_host, site_input.strip()]
                items, seen = [], set()
                for q in queries:
                    res_items = kg_search(q, api_key=api_key.strip(), languages=lang, limit=limit, types=types or None)
                    for it in res_items:
                        rid = (it.get("result") or {}).get("@id")
                        if rid and rid in seen:
                            continue
                        seen.add(rid)
                        items.append(it)

                choice = choose_best_result(items, target_host)
                if not choice:
                    st.warning("No encontré una entidad con ID válido (/m o /g) para ese sitio.\n"
                               "Prueba: cambia 'Idioma' a 'en' o agrega 'WebSite' en Types.")
                else:
                    res, kgid = choice
                    token = cp_token_from_kgid(kgid)
                    url = cp_url_from_kgid(kgid)

                    st.success("¡Listo! ID encontrado.")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Host:**", target_host)
                        st.write("**Nombre (KG):**", res.get("name", ""))
                        st.write("**Descripción:**", res.get("description", ""))
                        st.write("**Tipos:**", ", ".join(res.get("@type", [])))
                    with col2:
                        st.write("**ID (KG):**", f"`{kgid}`")
                        st.write("**Token (base64url):**")
                        st.code(token, language="text")
                        st.link_button("Abrir URL cp/", url)
                        st.text_input("Copiar URL cp/", url)

                    with st.expander("🔎 Resultado crudo del KG (item elegido)"):
                        st.json(res)

        except requests.HTTPError as e:
            st.error("Error HTTP consultando el KG. ¿API key correcta y API habilitada? ¿Cuotas disponibles?")
            st.exception(e)
        except requests.RequestException as e:
            st.error("Error de red consultando el KG.")
            st.exception(e)
        except Exception as e:
            st.error("Error procesando la respuesta.")
            st.exception(e)

st.divider()
with st.expander("💡 Tips de recuperación"):
    st.markdown(
        """
- Si no aparece nada, probá:
  - Cambiar **Idioma** a **en**.
  - Agregar **WebSite** en *Types* (algunas marcas sólo devuelven la entidad del sitio).
  - Usar la **homepage exacta** del medio como query (no una subruta).
- El ID puede ser **`/m/...`** (MID legado) o **`/g/...`** (ID nativo). Ambos funcionan para `cp/`.
- La URL final se arma codificando ese ID en un **mensaje protobuf (campo #1, length-delimited)** y luego **base64 URL-safe sin padding**.
        """
    )
