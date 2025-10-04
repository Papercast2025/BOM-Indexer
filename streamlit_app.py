import re
import json
import requests
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Papercast BOM Resolver", layout="wide")
st.title("Papercast BOM Resolver")
st.caption("Scan serial / comm ID → query CMS (controller or display) → map to Project/BOM via filename index")

# --- Secrets format (matches your existing [[cms]] array) ---
# [[cms]]
# name = "RTS"
# url = "https://rts.papercast.net/"
# username = "kbibby@papercast.com"
# password = "******"
#
# [[cms]]
# name = "Assured / UTA"
# url = "https://assured-uta.papercast.net"
# username = "kbibby@papercast.com"
# password = "******"
#
# Optional default if you don't upload in the UI:
# bom_index_path = "data/BOM_Index.csv"

# -------------------------- Helpers --------------------------

def get_instances_from_secrets():
    cms_list = st.secrets.get("cms", [])
    if isinstance(cms_list, dict):
        cms_list = [cms_list]
    instances = {entry["name"]: entry for entry in cms_list if "name" in entry}
    default_instance = next(iter(instances)) if instances else None
    return default_instance, instances

def login_session(base_url, username, password, timeout=15):
    s = requests.Session()
    url = base_url.rstrip("/") + "/rest/authentication/login"
    headers = {
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
    }
    resp = s.post(url, json={"username": username, "password": password}, headers=headers, timeout=timeout)
    resp.raise_for_status()
    if "JSESSIONID" not in s.cookies.get_dict():
        raise RuntimeError("Login ok but JSESSIONID cookie missing; check credentials/endpoint")
    return s

def _try_get(session, url, timeout=20):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
    }
    r = session.get(url, headers=headers, timeout=timeout)
    return r

def normalize_json(resp):
    # Return (is_ok, list_data, note)
    try:
        data = resp.json()
    except Exception:
        snippet = resp.text[:300].replace("\n", " ")
        return False, None, f"non-JSON {resp.status_code}: {snippet}"
    # common shapes
    if isinstance(data, dict):
        if isinstance(data.get("data"), list):
            return True, data["data"], "dict.data list"
        # any list value in dict
        for v in data.values():
            if isinstance(v, list):
                return True, v, "dict list value"
        # single record
        return True, [data], "wrapped single dict"
    if isinstance(data, list):
        return True, data, "list"
    return False, None, f"unexpected JSON type: {type(data).__name__}"

def fetch_any_listing(session, base_url, endpoint_candidates):
    probe_log = []
    for ep in endpoint_candidates:
        url = base_url.rstrip("/") + (ep if ep.startswith("/") else "/" + ep)
        try:
            resp = _try_get(session, url, timeout=25)
            ok, items, note = normalize_json(resp)
            probe_log.append({"endpoint": ep, "status": resp.status_code, "ok": ok, "note": note})
            if resp.status_code == 200 and ok and isinstance(items, list):
                return items, probe_log
        except Exception as e:
            probe_log.append({"endpoint": ep, "status": "ERR", "ok": False, "note": str(e)})
    return [], probe_log

def fetch_controllers(session, base_url, override=None):
    candidates = []
    if override:
        candidates.append(override)
    # broad set of controller endpoints
    candidates += [
        "/rest/admin/display-controller/list",
        "/rest/admin/display-controller",
        "/rest/display-controller/list",
        "/rest/display-controller",
        "/rest/display-controller/search",
        "/rest/display-controller/query",
        "/rest/display-controller?page=0&size=1000",
        "/rest/admin/display-controller?page=0&size=1000",
        "/api/admin/display-controller/list",
        "/api/display-controller/list",
        "/api/display-controller",
    ]
    return fetch_any_listing(session, base_url, candidates)

def fetch_displays(session, base_url, override=None):
    candidates = []
    if override:
        candidates.append(override)
    # broad set of display endpoints (older/newer variants)
    candidates += [
        "/rest/admin/display/list",
        "/rest/admin/display",
        "/rest/display/list",
        "/rest/display",
        "/api/admin/display/list",
        "/api/display/list",
        "/api/display",
    ]
    return fetch_any_listing(session, base_url, candidates)

def pick_matches(records, query):
    q = (query or "").strip().lower()
    if not q:
        return []
    fields = ["serial","serialNumber","commId","iccid","imei","controllerId","controller","deviceId","id","name","description"]
    hits = []
    for rec in records:
        # targeted fields first
        for k in fields:
            v = rec.get(k) if isinstance(rec, dict) else None
            if v and q in str(v).lower():
                hits.append(rec)
                break
        else:
            # fallback full-text search
            if q in json.dumps(rec, default=str).lower():
                hits.append(rec)
    return hits

PROJ_RX = re.compile(r'\b(SAL-[A-Z]+-\d{4}-\d+)\b', re.I)
SIZE_RX = re.compile(r'\bD(13|23|42)\b')

def parse_tokens(record: dict):
    text_fields = []
    for k in ["description","name","group","product","model"]:
        v = record.get(k)
        if v:
            text_fields.append(str(v))
    text = " | ".join(text_fields)
    proj = None
    size = None
    m1 = PROJ_RX.search(text)
    if m1:
        proj = m1.group(1)
    m2 = SIZE_RX.search(text)
    if m2:
        size = m2.group(1)
    return proj, size, text

@st.cache_data
def load_bom_index(path: str):
    if not path:
        return pd.DataFrame()
    if path.lower().endswith(".csv"):
        return pd.read_csv(path)
    return pd.read_excel(path)

# -------------------------- UI --------------------------

default_instance, instances = get_instances_from_secrets()
if not instances:
    st.error("No CMS instances configured (expected [[cms]] array in Secrets).")
    st.stop()

inst_names = list(instances.keys())
sel_instance = st.sidebar.selectbox("CMS instance", inst_names, index=0)

uploaded = st.sidebar.file_uploader("BOM_Index (.csv/.xlsx)", type=["csv","xlsx"])
if uploaded is not None:
    if uploaded.name.lower().endswith(".csv"):
        bom_index = pd.read_csv(uploaded)
    else:
        bom_index = pd.read_excel(uploaded)
else:
    bom_index = load_bom_index(st.secrets.get("bom_index_path", "data/BOM_Index.csv"))
st.sidebar.write(f"BOM rows loaded: {len(bom_index)}")

query = st.text_input("Scan/paste Display Serial / Comm ID / Controller ID")
endpoint_override = st.text_input("Optional endpoint override (e.g., /rest/display-controller/list)")
use_display_fallback = st.checkbox("Also probe DISPLAY endpoints (not just controllers)", value=True)

if st.button("Resolve"):
    cfg = instances[sel_instance]
    base_url = cfg.get("url") or cfg.get("base_url")
    username = cfg.get("username")
    password = cfg.get("password")
    if not all([base_url, username, password]):
        st.error("Missing url/username/password in secrets for the selected instance.")
        st.stop()

    with st.status("Logging in...", expanded=False) as s1:
        try:
            sess = login_session(base_url, username, password)
            s1.update(label="Logged in", state="complete")
        except Exception as e:
            s1.update(label=f"Login failed: {e}", state="error")
            st.stop()

    with st.status("Fetching CONTROLLERS...", expanded=False) as s2:
        controllers, probe_log_ctrl = fetch_controllers(sess, base_url, endpoint_override)
        if controllers:
            s2.update(label=f"Fetched {len(controllers)} controller records", state="complete")
        else:
            s2.update(label=f"No controller endpoint succeeded", state="error")

    displays = []
    probe_log_disp = []
    if use_display_fallback:
        with st.status("Fetching DISPLAYS (fallback)...", expanded=False) as s3:
            displays, probe_log_disp = fetch_displays(sess, base_url, endpoint_override)
            if displays:
                s3.update(label=f"Fetched {len(displays)} display records", state="complete")
            else:
                s3.update(label=f"No display endpoint succeeded", state="error")

    st.subheader("Endpoint probe report")
    st.write("Controllers:")
    st.dataframe(pd.DataFrame(probe_log_ctrl))
    if use_display_fallback:
        st.write("Displays:")
        st.dataframe(pd.DataFrame(probe_log_disp))

    records = controllers if controllers else displays
    if not records:
        st.error("Fetch failed: no usable controllers or displays endpoint responded with list JSON. Adjust override or confirm the tenant's API path.")
        st.stop()

    matches = pick_matches(records, query)
    st.subheader("Matches")
    st.write(f"{len(matches)} matched")
    if matches:
        st.dataframe(pd.json_normalize(matches))
    else:
        st.info("No matches; try a different identifier.")

    parsed = []
    for m in matches:
        proj, size, blob = parse_tokens(m)
        parsed.append({
            "id": m.get("id") or m.get("controllerId") or m.get("deviceId"),
            "description": m.get("description"),
            "project_code": proj,
            "size_token": size,
            "raw_text": blob
        })
    df_parsed = pd.DataFrame(parsed)
    st.subheader("Parsed tokens")
    if not df_parsed.empty:
        st.dataframe(df_parsed)
    else:
        st.info("No tokens parsed from matches.")

    st.subheader("BOM candidates")
    if bom_index is None or bom_index.empty:
        st.warning("No BOM index loaded. Upload BOM_Index or set bom_index_path in secrets.")
    else:
        candidates = bom_index.copy()
        if not df_parsed.empty:
            proj_vals = [p for p in df_parsed["project_code"].dropna().unique()]
            size_vals = [s for s in df_parsed["size_token"].dropna().unique()]
            if proj_vals:
                candidates = candidates[candidates["ProjectCode"].isin(proj_vals)]
            if size_vals:
                mask = False
                for s in size_vals:
                    mask = mask | candidates["ModelToken"].astype(str).str.contains(f"D{s}", case=False, na=False)                                 | candidates["FileName"].astype(str).str.contains(f"D{s}", case=False, na=False)
                candidates = candidates[mask] if hasattr(mask, "__len__") else candidates

        st.dataframe(candidates)
        if not candidates.empty:
            choice = st.selectbox("Pick BOM file", candidates["FileName"].tolist())
            selected = candidates[candidates["FileName"] == choice].iloc[0].to_dict()
            st.json(selected)
            payload = {
                "Resolved_ProjectCode": selected.get("ProjectCode"),
                "Resolved_DisplaySize": selected.get("DisplaySize"),
                "Resolved_BOM_File": selected.get("FileName"),
                "Resolver_Status": "Matched",
                "Resolver_Notes": "Matched via description/group tokens"
            }
            st.download_button("Download resolver payload (JSON)", data=json.dumps(payload, indent=2), file_name="resolver_payload.json")