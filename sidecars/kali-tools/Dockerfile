# ---------------------------------------------------------------------------
# Kali-tools sidecar — opt-in container that adds the full Kali Linux toolset
# alongside the existing auto-bughunter sidecars (nmap, gobuster, sqlmap, etc.)
# that are already baked into the platform.  This sidecar provides tools that
# are *not* already covered by the existing containers:
#
#   • Network reconnaissance: masscan, ncat, socat
#   • Authentication testing: hydra, hashcat, john
#   • Web fingerprinting: whatweb, wafw00f, dnsrecon, sslyze
#   • TLS deep inspection: testssl.sh
#   • Directory brute-force: wfuzz, feroxbuster
#   • Metadata extraction: exiftool, binwalk
#   • Wordlists: seclists
#   • Utilities: curl, wget, python3, pip3
#
# The container keeps running indefinitely (tail -f /dev/null) so the backend
# can exec into it via the Docker daemon socket to run tool commands.
#
# Start with the kali profile:
#   docker compose --profile kali up -d kali-tools
#
# Execute a tool:
#   docker compose exec kali-tools nmap -sV -T4 <target>
#   docker compose exec kali-tools hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:F=invalid"
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Refresh package index and install tools in a single layer to keep image size
# manageable. Use --no-install-recommends to avoid pulling in unneeded deps.
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        # Network/port scanning
        masscan \
        ncat \
        socat \
        # Authentication brute-force
        hydra \
        hashcat \
        john \
        # Web fingerprinting & WAF detection
        whatweb \
        wafw00f \
        # DNS reconnaissance
        dnsrecon \
        # TLS/SSL testing
        sslyze \
        testssl.sh \
        # Web directory brute-force
        wfuzz \
        feroxbuster \
        # Metadata & binary analysis
        libimage-exiftool-perl \
        binwalk \
        # Wordlists (provides /usr/share/seclists)
        seclists \
        # General utilities
        curl \
        wget \
        python3 \
        python3-pip \
        # Required by many Kali tools at runtime
        libpcap-dev \
        iputils-ping \
        net-tools \
        procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Smoke-test: verify the core tools are executable.
# This runs at build time so a broken package will fail the image build rather
# than failing silently at scan time.
RUN nmap --version > /dev/null && \
    hydra -h 2>/dev/null | head -1 && \
    whatweb --version 2>/dev/null | head -1 && \
    feroxbuster --version && \
    echo "kali-tools smoke-test passed"

# Healthcheck: verify at least one primary tool is on the PATH.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD nmap --version > /dev/null 2>&1 || exit 1

# Keep the container alive so the backend can exec commands into it.
ENTRYPOINT ["tail", "-f", "/dev/null"]
