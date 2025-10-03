# Papercast BOM Resolver (Standalone)

## Deploy on Streamlit Cloud
- **Repository**: `papercast2025/repo`
- **Branch**: `master`
- **Main file path**: `streamlit_app.py`
- **App URL (optional)**: `.streamlit.app`

## Secrets (Streamlit Cloud → App → Settings → Secrets)
```toml
[cms]
default_instance = "LA_Metro"

[cms.instances.LA_Metro]
base_url = "https://lametro.papercast.net"
username = "YOUR_USERNAME"
password = "YOUR_PASSWORD"
controllers_endpoint = "/rest/display-controller/list"

[cms.instances.Caltrain]
base_url = "https://caltrain.papercast.net"
username = "YOUR_USERNAME"
password = "YOUR_PASSWORD"

# Optional default if you don't upload a file in the sidebar
bom_index_path = "data/BOM_Index.csv"
```

## BOM index
Place `data/BOM_Index.csv` in the repo (or upload during use). Columns:
- ProjectCode, DisplaySize, FileName, FilePath, ModelToken
