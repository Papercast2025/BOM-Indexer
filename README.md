# Papercast BOM Resolver (v3)

- Supports your `[[cms]]` secrets array.
- Probes a wider set of controller **and** display endpoints.
- Shows a probe report so you can see exactly which path returned data.

## Deploy on Streamlit Cloud
- Repository: `papercast2025/repo`
- Branch: `master`
- Main file path: `streamlit_app.py`

## Secrets
Use your existing format, e.g.:
```toml
[[cms]]
name = "RTS"
url = "https://rts.papercast.net/"
username = "kbibby@papercast.com"
password = "******"

[[cms]]
name = "Assured / UTA"
url = "https://assured-uta.papercast.net"
username = "kbibby@papercast.com"
password = "******"

# Optional default if you don't upload in the UI
bom_index_path = "data/BOM_Index.csv"
```

## BOM Index
Commit one at `data/BOM_Index.csv` or upload at runtime from the sidebar.
