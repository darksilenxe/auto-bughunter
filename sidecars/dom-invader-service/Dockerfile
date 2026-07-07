FROM python:3.12-slim

# Install system dependencies required by Playwright's Chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Playwright's --with-deps tries to install ttf-unifont and ttf-ubuntu-font-family
# which no longer exist in Debian Bookworm (python:3.12-slim base).  Build stub
# .deb packages for those names, publish them via a temporary local apt repository,
# and install the real successor font (fonts-unifont) so Chromium can render text.
RUN apt-get update && \
    apt-get install -y --no-install-recommends fonts-unifont && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /tmp/apt-local && \
    for pkg in ttf-unifont ttf-ubuntu-font-family; do \
        mkdir -p /tmp/fakepkg/DEBIAN && \
        printf 'Package: %s\nVersion: 1\nArchitecture: all\nMaintainer: stub\nDescription: stub\n' \
            "$pkg" > /tmp/fakepkg/DEBIAN/control && \
        dpkg-deb --build /tmp/fakepkg "/tmp/apt-local/${pkg}_1_all.deb" && \
        rm -rf /tmp/fakepkg; \
    done && \
    python3 -c 'import os,hashlib;pkgs=["ttf-unifont","ttf-ubuntu-font-family"];entries=[];[entries.append("Package: "+p+"\nVersion: 1\nArchitecture: all\nMaintainer: stub\nDescription: stub\nFilename: "+p+"_1_all.deb\nSize: "+str(os.path.getsize("/tmp/apt-local/"+p+"_1_all.deb"))+"\nSHA256: "+hashlib.sha256(open("/tmp/apt-local/"+p+"_1_all.deb","rb").read()).hexdigest()+"\n") for p in pkgs];open("/tmp/apt-local/Packages","w").write("\n".join(entries))' && \
    echo 'deb [trusted=yes] file:///tmp/apt-local /' >> /etc/apt/sources.list && \
    apt-get update

# Install Playwright Chromium browser and its OS-level dependencies.
# --with-deps installs the necessary system libraries (libnss3, etc.) so the
# browser runs inside the slim Python image without a full desktop environment.
RUN playwright install chromium --with-deps && \
    rm -rf /tmp/apt-local

COPY app /app/app

EXPOSE 8097

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8097"]
