# GitHub Wiki (14 pages)

This folder contains Markdown pages you can copy into the GitHub Wiki for this repository.

## How to publish to GitHub Wiki

GitHub Wikis are separate git repositories. You can publish these pages in either way:

1) **Manual (simple):** create pages in the GitHub UI and paste the contents from `wiki/pages/`.

2) **Git-based sync (recommended):**

- Clone the wiki repo:

```powershell
git clone https://github.com/aryandiastech/Global-Honeypot-Threat-Map.wiki.git
```

- Copy pages:

```powershell
Copy-Item -Recurse -Force .\\wiki\\pages\\* .\\Global-Honeypot-Threat-Map.wiki\\
Copy-Item -Force .\\wiki\\_Sidebar.md .\\Global-Honeypot-Threat-Map.wiki\\_Sidebar.md
```

- Commit and push:

```powershell
cd .\\Global-Honeypot-Threat-Map.wiki
git add .
git commit -m \"Add project wiki pages\"
git push
```

