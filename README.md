# Papercast BOM Resolver (Standalone, [[cms]] secrets)

## Deploy on Streamlit Cloud
- **Repository**: `papercast2025/repo`
- **Branch**: `master`
- **Main file path**: `streamlit_app.py`

## Secrets (matches your existing format)
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

# Optional default if you don't upload a file in the sidebar
bom_index_path = "data/BOM_Index.csv"
```
