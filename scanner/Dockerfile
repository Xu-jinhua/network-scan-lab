FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      ffuf \
      dirb \
      git \
      gobuster \
      golang \
      metasploit-framework \
      nmap \
      nikto \
      python3 \
      python3-pip \
      sqlmap \
      testssl.sh \
      whatweb \
      zaproxy && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/owasp-amass/amass/v4/...@master

ENV PATH="/root/go/bin:${PATH}"

COPY requirements.txt /app/requirements.txt
RUN pip3 install --break-system-packages -r /app/requirements.txt

COPY scanner.py /app/scanner.py

ENTRYPOINT ["python3", "/app/scanner.py"]
