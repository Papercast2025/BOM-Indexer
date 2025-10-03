import re
import json
import requests
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Papercast BOM Resolver", layout="wide")

st.title("Papercast BOM Resolver")
st.caption("Scan serial / comm ID → query CMS Display Controllers → map to Project/BOM via filename index")

# Secrets format (same pattern as your existing dashboard)
# In Streamlit Cloud, set these in the app's Secrets (not in the repo):
#
# [cms]
# default_instance = "LA_Metro"
#
# [cms.instances.LA_Metro]
# base_url = "https://lametro.papercast.net"
# username = "YOUR_USERNAME"
# password = "YOUR_PASSWORD"
# controllers_endpoint = "/rest/display-controller/list"  # optional override
#
# [cms.instances.Caltrain]
# base_url = "https://caltrain.papercast.net"
# username = "YOUR_USERNAME"
# password = "YOUR_PASSWORD"
#
# # Optional default if you don't upload the file in the UI:
# bom_index_path = "data/BOM_Index.csv"

def get_instances_from_secrets():
    cms = st.secrets.get("cms", {})
    default_instance = cms.get("default_instance")
    instances = cms.get("instances", {})
    return default_instance, instances

def login_session(base_url, username, password, timeout=15):
    s = requests.Session()
    url = base_url.rstrip("/") + "/rest/authentication/login"
    resp = s.post(url, json={"username": username, "password": password}, timeout=timeout)
    resp.raise_for_status()
    if "JSESSIONID" not in s.cookies.get_dict():
        raise RuntimeError("Login ok but JSESSIONID cookie missing; check credentials/endpoint")
    return s

def fetch_controllers(session, base_url, endpoint=None, timeout=20):
    candidates = []
    if endpoint:
        candidates.append(endpoint)
    candidates += ["/rest/display-controller/list", "/rest/admin/display-controller/list"]
    errors = []
    for ep in candidates:
        url = base_url.rstrip("/") + ep
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    errors.append(f"{ep} → non-JSON {r.status_code}")
                    continue
                # Common response shapes
                if isinstance(data, dict) and "data" in data and isinstance(data["data"], list):
                    return data["data"]
                if isinstance(data, list):
                    return data
                # Fallback: first list value inside dict
                for v in data.values():
                    if isinstance(v, list):
                        return v
                return []
            else:
                errors.append(f"{ep} → {r.status_code}")
        except Exception as e:
            errors.append(f"{ep} → {e}")
    raise RuntimeError("Unable to fetch controllers. Tried: " + " | ".join(errors))

def pick_matches(controllers, query):
    q = (query or "").strip().lower()
    if not q:
        return []
    hits = []
    for c in controllers:
        # try common fields first
        for k in ["serial","serialNumber","commId","iccid","imei","controllerId","id","name","description"]:
            v = c.get(k) if isinstance(c, dict) else None
            if v and q in str(v).lower():
                hits.append(c); break
        else:
            # final fallback: full-text JSON
            if q in json.dumps(c, default=str).lower():
                hits.append(c)
    return hits

PROJ_RX = re.compile(r'\\b(SAL-[A-Z]+-\\d{4}-\\d+)\\b', re.I)
SIZE_RX = re.compile(r'\\bD(13|23|42)\\b')

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

# Sidebar: instance + BOM index
default_instance, instances = get_instances_from_secrets()
if not instances:
    st.error("No CMS instances configured in secrets.")
    st.stop()

inst_names = list(instances.keys())
sel_instance = st.sidebar.selectbox(
    "CMS instance",
    inst_names,
    index=max(0, inst_names.index(default_instance) if default_instance in inst_names else 0)
)

uploaded = st.sidebar.file_uploader("BOM_Index (.csv/.xlsx)", type=["csv","xlsx"])
if uploaded is not None:
    if uploaded.name.lower().endswith(".csv"):
        bom_index = pd.read_csv(uploaded)
    else:
        bom_index = pd.read_excel(uploaded)
else:
    bom_index = load_bom_index(st.secrets.get("bom_index_path", "data/BOM_Index.csv"))
st.sidebar.write(f"BOM rows loaded: {len(bom_index)}")

# Main UI
query = st.text_input("Scan/paste Display Serial / Comm ID / Controller ID")
btn = st.button("Resolve")

if btn:
    cfg = instances[sel_instance]
    base_url = cfg.get("base_url")
    username = cfg.get("username")
    password = cfg.get("password")
    endpoint = cfg.get("controllers_endpoint", "/rest/display-controller/list")

    if not all([base_url, username, password]):
        st.error("Missing base_url/username/password in secrets for the selected instance.")
        st.stop()

    with st.status("Logging in...", expanded=False) as s1:
        try:
            sess = login_session(base_url, username, password)
            s1.update(label="Logged in", state="complete")
        except Exception as e:
            s1.update(label=f"Login failed: {e}", state="error")
            st.stop()

    with st.status("Fetching display controllers...", expanded=False) as s2:
        try:
            controllers = fetch_controllers(sess, base_url, endpoint)
            s2.update(label=f"Fetched {len(controllers)} controllers", state="complete")
        except Exception as e:
            s2.update(label=f"Fetch failed: {e}", state="error")
            st.stop()

    matches = pick_matches(controllers, query)
    st.subheader("Controller matches")
    st.write(f"{len(matches)} matched")
    if matches:
        st.dataframe(pd.json_normalize(matches))
    else:
        st.info("No matches found. Try a different identifier.")

    parsed = []
    for m in matches:
        proj, size, blob = parse_tokens(m)
        parsed.append({
            "controller_id": m.get("id") or m.get("controllerId"),
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
        st.info("No tokens parsed from matches. (Check description/group fields.)")

    # Map to BOM index
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
                    mask = mask | candidates["ModelToken"].astype(str).str.contains(f"D{s}", case=False, na=False) \
                                | candidates["FileName"].astype(str).str.contains(f"D{s}", case=False, na=False)
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
                "Resolver_Notes": "Matched via description tokens"
            }
            st.download_button("Download resolver payload (JSON)", data=json.dumps(payload, indent=2), file_name="resolver_payload.json")