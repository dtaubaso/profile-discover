# app.py
import base64
import re
import requests
import streamlit as st
from urllib.parse import urlparse

KG_ENDPOINT = "https://kgsearch.googleapis.com/v1/entities:search"
ID_RE = re.compile(r"^/(m|g)/[0-9a-z_]+$")  # acepta /m/... o /g/...

# ========== Helpers de codificación ==========

def b64url_nopad_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def varint_encode(n: int) -> bytes:
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

def encode_profile_token_from_kgid(kgid: str) -> str:
    """
    kgid: '/m/07k2d' o '/g/11xxxx'
    """
    if not ID_RE.match(kgid):
        raise ValueError("ID inválido (esperado '/m/...' o '/g/...').")
    payload = kgid.encode("utf-8")
    proto = bytes([0x0A]) + varint_encode(len(payload)) + payload  # field #1, length-delimited
    return b64url_nopad_encode(proto)

def build_profile_url(token: str) -> str:
    return f"https://profile.google.com/cp/{token}"

# ========== Normalización de URL / dominio ==========

def normalize_host(site_url: str) -> str:
    """
    Devuelve el host 'limpio': sin esquema ni 'www.'.
    """
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

# ========== Knowledge Graph Search ==========

def extract_id_from_result(res: dict) -> str | None:
    """
    Lee '@id' (o 'id'), quita prefijo 'kg:' si está, y valida /m o /g.
    """
    kg_id = res.get("@id") or res.get("id")
    if not kg_id:
        return None
    if kg_id.startswith("kg:"):
        kg_id = kg_id[3:]
    return kg_id if ID_RE.match(kg_id) else None

@st.cache_data(show_spinner=False, ttl=1800)
def kg_search_by_query(query: str, api_key: str, languages: str = "es", limit: int = 10, types: list[str] | None = None):
    """
    Llama a KG Search. Si 'types' incluye varios, combina resultados.
    """
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

def choose_best_result(items: list[dict], target_host: str) -> tuple[dict, str] | None:
    """
    Heurística: prioriza coincidencia exacta por dominio en result.url,
    luego por sameAs, luego por score.
    """
    scored = []
    for it in items:
        res = it.get("result", {})
        kgid = extract_id_from_result(res)
        if not kgid:
            continue
        score = 0
        res_url_host = host_of(res.get("url"))
        if res_url_host == target_host:
            score += 100
        # sameAs puede incluir varias URLs (redes sociales, etc.)
        same_as = res.get("sameAs") or []
        if isinstance(same_as, str):
            same_as = [same_as]
        for s in same_as:
            if host_of(s) == target_host:
                score += 40
                break
        # si el nombre contiene el dominio "despuntado" suma un poco
        name = (res.get("name") or "").lower()
        if target_host.split(".")[0] in name:
            score += 5
        # resultado nativo
        result_score = it.get("resultScore") or 0.0
        score += float(result_score)
        scored.append((score, res, kgid))
    if not scored:
        return None
    scored.sort(key=lambda x: x[0], reverse=True)
    _, res, kgid = scored[0]
    return res, kgid

# ========== UI de Streamlit ==========

st.set_page_config(page_title="URL → (/g|/m) → cp-token", page_icon="🧩", layout="centered")
st.title("🧩 De URL del sitio → ID `/g` o `/m` → token `cp/` de Google Profile")

with st.sidebar:
    st.header("🔐 Credenciales")
    default_key = st.secrets.get("GOOGLE_API_KEY", "")
    api_key = st.text_input("Google API Key", value=default_key, type="password", help="Debe tener habilitada la Knowledge Graph Search API.")
    st.header("🔧 Opciones")
    lang = st.selectbox("Idioma (languages)", ["es", "en", "pt", "fr", "de"], index=0)
    limit = st.slider("Resultados (por tipo)", 1, 20, 10)
    types = st.multiselect(
        "Types (schema.org, opcional)",
        ["Organization","Corporation","NewsMediaOrganization","Newspaper","Brand","Person","Place","MusicGroup","TVSeries"],
        default=["Organization","Corporation","Brand"]
    )

site_input = st.text_input("Pegá la URL del sitio (ej: https://www.clarin.com/)", "")

if st.button("Buscar ID en Knowledge Graph", disabled=(not site_input.strip() or not api_key.strip())):
    if not api_key.strip():
        st.error("Falta la API key.")
    else:
        try:
            target_host = normalize_host(site_input)
            with st.spinner(f"Buscando entidad del KG para: {target_host} …"):
                # Probamos con dominio y con URL completa como queries
                queries = [target_host, site_input.strip()]
                items = []
                seen = set()
                for q in queries:
                    res_items = kg_search_by_query(q, api_key=api_key.strip(), languages=lang, limit=limit, types=types or None)
                    for it in res_items:
                        # deduplicar por @id si existe
                        rid = (it.get("result", {}) or {}).get("@id")
                        if rid and rid in seen:
                            continue
                        seen.add(rid)
                        items.append(it)

                choice = choose_best_result(items, target_host)
                if not choice:
                    st.warning("No encontré una entidad con ID válido (/m o /g) que coincida con ese sitio.")
                else:
                    res, kgid = choice
                    token = encode_profile_token_from_kgid(kgid)
                    url = build_profile_url(token)
                    st.success("¡Listo!")
                    st.write("**Sitio (host):**", target_host)
                    st.write("**Nombre (KG):**", res.get("name", ""))
                    st.write("**Descripción:**", res.get("description", ""))
                    st.write("**Tipos:**", ", ".join(res.get("@type", [])))
                    st.write("**ID (KG):**", f"`{kgid}`  ← (puede ser `/g/...` o `/m/...`)")
                    st.write("**Token (base64url):**")
                    st.code(token, language="text")
                    st.link_button("Abrir URL cp/", url)
                    st.text_input("Copiar URL cp/", url)

                    with st.expander("Campos crudos devueltos por el KG (resultado elegido)"):
                        st.json(res)

        except requests.HTTPError as e:
            st.error("Error HTTP al consultar el KG. ¿API key correcta y API habilitada? ¿Cuotas disponibles?")
            st.exception(e)
        except requests.RequestException as e:
            st.error("Error de red consultando el KG.")
            st.exception(e)
        except Exception as e:
            st.error("Error procesando la respuesta.")
            st.exception(e)

st.divider()
with st.expander("❓Notas"):
    st.markdown(
        """
- La búsqueda usa el **dominio** y la **URL** como *query* en Knowledge Graph Search y prioriza resultados donde:
  1) `result.url` coincide en dominio con tu entrada,  
  2) o alguna URL en `result.sameAs` coincide,  
  3) y como desempate usa `resultScore`.
- El ID puede ser **`/m/...`** (MID heredado de Freebase) o **`/g/...`** (ID nativo de Google).
- El token `cp/` se arma como **protobuf** (campo 1, length-delimited) con el ID, codificado en **base64 URL-safe** sin padding.
        """
    )
