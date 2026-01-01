import re
import time
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any

import requests
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup

# NLTK (résumé simple via extraction de phrases)
import nltk
from nltk.tokenize import sent_tokenize

try:
    from .base_collector import BaseCollector
except ImportError:
    # Exécution directe (python collectors/docker_k8s_collector.py)
    from base_collector import BaseCollector

# ----------------------------
# Config
# ----------------------------

USER_AGENT = "BeyLink12345-DevSecOps-Collector/1.0 (+Docker-K8s)"
TIMEOUT = 20

KEYWORDS_DOCKER = [
    "docker", "docker desktop", "docker engine", "moby", "buildkit", "dockerfile",
    "containerd", "runc", "oci", "registry", "image", "container escape", "cgroups"
]
KEYWORDS_K8S = [
    "kubernetes", "k8s", "kubelet", "apiserver", "api server", "etcd", "rbac", "helm",
    "ingress", "cni", "cri", "cluster", "admission controller"
]

SECURITY_TERMS = [
    "cve", "vulnerability", "exploit", "rce", "privilege escalation", "escape",
    "dos", "denial of service", "auth bypass", "sandbox", "malicious", "security update",
    "critical", "high severity", "patch", "fixed"
]

# Sources (RSS + HTTP)
SOURCES = [
    # Docker
    {"id": "docker_blog", "name": "Docker Blog", "type": "rss",
     "url": "https://www.docker.com/blog/feed/"},
    {"id": "docker_security", "name": "Docker Security Announcements", "type": "http",
     "url": "https://docs.docker.com/engine/security/"},
    {"id": "moby_security", "name": "Moby Security", "type": "http",
     "url": "https://github.com/moby/moby/security/advisories"},
    # Kubernetes / CNCF
    {"id": "k8s_blog", "name": "Kubernetes Blog", "type": "rss",
     "url": "https://kubernetes.io/feed.xml"},
    {"id": "k8s_security_ann", "name": "Kubernetes Security Announcements", "type": "http",
     "url": "https://kubernetes.io/docs/reference/issues-security/security/"},
    {"id": "cncf_blog", "name": "CNCF Blog", "type": "rss",
     "url": "https://www.cncf.io/blog/feed/"},
    # GitHub advisories (topics)
    {"id": "github_advisories_containers", "name": "GitHub Advisories (containers)", "type": "http",
     "url": "https://github.com/advisories?query=container"},
    {"id": "github_advisories_kubernetes", "name": "GitHub Advisories (kubernetes)", "type": "http",
     "url": "https://github.com/advisories?query=kubernetes"},
]

CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


# ----------------------------
# Utils texte / scoring
# ----------------------------

def ensure_nltk():
    """Assure que 'punkt' est dispo."""
    try:
        nltk.data.find("tokenizers/punkt")
    except LookupError:
        nltk.download("punkt", quiet=True)


def normalize_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip())


def extract_cves(text: str) -> List[str]:
    if not text:
        return []
    return sorted(set(m.group(0).upper() for m in CVE_REGEX.finditer(text)))


def guess_ecosystem(text: str) -> str:
    t = (text or "").lower()
    score_d = sum(1 for k in KEYWORDS_DOCKER if k in t)
    score_k = sum(1 for k in KEYWORDS_K8S if k in t)
    if score_d == 0 and score_k == 0:
        return ""
    return "Docker" if score_d >= score_k else "Kubernetes"


def severity_from_text(text: str) -> str:
    t = (text or "").lower()
    # heuristique simple
    if "critical" in t or "rce" in t or "remote code execution" in t:
        return "CRITICAL"
    if "high" in t or "privilege escalation" in t or "escape" in t:
        return "HIGH"
    if "medium" in t or "dos" in t or "denial of service" in t:
        return "MEDIUM"
    if "low" in t:
        return "LOW"
    return "UNKNOWN"


def risk_score_guess(text: str, cves: List[str]) -> float:
    """Score heuristique 0..10."""
    t = (text or "").lower()
    base = 0.0
    base += 2.0 * min(len(cves), 3)          # CVE présentes -> +2 chacune max 3
    base += 2.5 if "critical" in t else 0.0
    base += 1.5 if "high" in t else 0.0
    base += 1.5 if "rce" in t else 0.0
    base += 1.0 if "escape" in t else 0.0
    base += 1.0 if "auth bypass" in t else 0.0
    base += 0.5 if "patch" in t or "fixed" in t else 0.0
    return float(max(0.0, min(10.0, base)))


def summarize_text(text: str, max_sentences: int = 2) -> str:
    ensure_nltk()
    text = normalize_text(text)
    if not text:
        return ""
    sents = sent_tokenize(text)
    if len(sents) <= max_sentences:
        return text
    return " ".join(sents[:max_sentences])


# ----------------------------
# Fetchers
# ----------------------------

def http_get(url: str) -> Optional[str]:
    try:
        r = requests.get(
            url,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        if r.status_code >= 200 and r.status_code < 300:
            return r.text
        return None
    except Exception:
        return None


def fetch_rss(url: str, source_name: str) -> List[Dict[str, Any]]:
    """Parse RSS basique via BeautifulSoup (XML)."""
    xml = http_get(url)
    if not xml:
        return []

    soup = BeautifulSoup(xml, "xml")
    items = []
    for it in soup.find_all("item"):
        title = normalize_text(it.title.get_text()) if it.title else ""
        link = normalize_text(it.link.get_text()) if it.link else ""
        desc = normalize_text(it.description.get_text()) if it.description else ""
        pub = ""
        if it.pubDate:
            pub = normalize_text(it.pubDate.get_text())
        items.append({
            "source_name": source_name,
            "title": title,
            "url": link,
            "raw_text": f"{title} {desc} {pub}",
            "published_raw": pub,
        })
    return items


def fetch_http_page(url: str, source_name: str) -> List[Dict[str, Any]]:
    """Scraping très simple: titre + quelques extraits."""
    html = http_get(url)
    if not html:
        return []

    soup = BeautifulSoup(html, "html.parser")
    title = normalize_text(soup.title.get_text()) if soup.title else source_name
    # prend un extrait du texte visible
    text = normalize_text(soup.get_text(" ", strip=True))
    # coupe pour éviter les payloads énormes
    text = text[:4000]

    return [{
        "source_name": source_name,
        "title": title,
        "url": url,
        "raw_text": f"{title} {text}",
        "published_raw": "",
    }]


# ----------------------------
# Normalisation dates (simple)
# ----------------------------

def parse_date_to_yyyy_mm_dd(s: str) -> Optional[str]:
    s = normalize_text(s)
    if not s:
        return None

    # Essai RFC822 (RSS)
    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
        try:
            d = datetime.strptime(s, fmt)
            return d.date().isoformat()
        except Exception:
            pass

    # fallback: essaie d’extraire yyyy-mm-dd
    m = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", s)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"

    return None


# ----------------------------
# Collecte principale (DataFrame)
# ----------------------------

def collect_all() -> pd.DataFrame:
    rows: List[Dict[str, Any]] = []

    for src in SOURCES:
        stype = src.get("type")
        url = src.get("url")
        name = src.get("name", src.get("id", "Unknown"))

        if not url:
            continue

        if stype == "rss":
            items = fetch_rss(url, name)
        else:
            items = fetch_http_page(url, name)

        for it in items:
            raw_text = normalize_text(it.get("raw_text", ""))
            ecosystem = guess_ecosystem(raw_text)
            cves = extract_cves(raw_text)
            sev = severity_from_text(raw_text)
            risk = risk_score_guess(raw_text, cves)
            summary = summarize_text(raw_text, max_sentences=2)

            published = parse_date_to_yyyy_mm_dd(it.get("published_raw", ""))

            # Filtre léger : garde si mention sécurité OU CVE OU mots-clés Docker/K8s
            t = raw_text.lower()
            is_securityish = any(term in t for term in SECURITY_TERMS)
            is_topic = any(k in t for k in KEYWORDS_DOCKER + KEYWORDS_K8S)

            if not (is_securityish or cves or is_topic):
                continue

            rows.append({
                "ecosystem": ecosystem,
                "source_id": src.get("id"),
                "source_name": it.get("source_name", name),
                "title": it.get("title", ""),
                "url": it.get("url", url),
                "published": published,
                "cves": cves,
                "severity_guess": sev,
                "risk_score_guess": risk,
                "summary": summary,
            })

        # mini pause
        time.sleep(0.3)

    if not rows:
        return pd.DataFrame(columns=[
            "ecosystem", "source_id", "source_name", "title", "url", "published",
            "cves", "severity_guess", "risk_score_guess", "summary"
        ])

    df = pd.DataFrame(rows)

    # nettoyage de base
    df["cves"] = df["cves"].apply(lambda x: x if isinstance(x, list) else [])
    df["ecosystem"] = df["ecosystem"].fillna("").astype(str)
    df["severity_guess"] = df["severity_guess"].fillna("UNKNOWN").astype(str)

    # garde les plus “risqués” en premier
    df = df.sort_values(by=["risk_score_guess"], ascending=False).reset_index(drop=True)

    return df


# ============================================================
# VTBDA adapter: DataFrame -> List[Dict] attendu par BaseCollector
# ============================================================

def to_vtbda_vulnerabilities(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Convertit le DataFrame collect_all() en items compatibles BaseCollector.save_to_database()

    BaseCollector décide:
      - package vuln si (ecosystem AND package) existent
      - sinon CVE générale (vuln_id)
    """
    if df is None or df.empty:
        return []

    collected_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    out: List[Dict[str, Any]] = []

    for r in df.to_dict(orient="records"):
        ecosystem = (r.get("ecosystem") or "").strip()
        title = (r.get("title") or "").strip()
        url = (r.get("url") or "").strip()
        published = r.get("published")
        severity = (r.get("severity_guess") or "UNKNOWN").upper()
        summary = (r.get("summary") or "").strip() or title
        cves = r.get("cves") or []
        source_name = (r.get("source_name") or r.get("source_id") or "DockerK8s").strip()

        references = [url] if url else []

        # 1) Si CVE(s) => 1 item par CVE (CVE générale)
        if isinstance(cves, list) and len(cves) > 0:
            for cve in cves:
                out.append({
                    "source": source_name,
                    "vuln_id": cve,                      # BaseCollector -> insert_cve()
                    "severity": severity,
                    "summary": f"{title} — {summary}"[:1000],
                    "references": references,
                    "published": published,
                    "collected_at": collected_at,
                })
        else:
            # 2) Advisory sans CVE => package vuln minimal (Docker/Kubernetes)
            package_name = (ecosystem or "docker-k8s").lower()
            out.append({
                "source": source_name,
                "package": package_name,                 # BaseCollector -> insert_package_vulnerability()
                "ecosystem": ecosystem or "DockerK8s",
                "severity": severity,
                "summary": f"{title} — {summary}"[:1000],
                "references": references,
                "published": published,
                "collected_at": collected_at,
                "affected_versions": "",
            })

    return out


# ============================================================
# VTBDA Collector class (comme OSVGitHubCollector)
# ============================================================

class DockerK8sCollector(BaseCollector):
    """Collecteur Docker/Kubernetes intégré à VTBDA (RSS + HTTP)."""

    def __init__(self):
        super().__init__(name="DockerK8sCollector")

    def collect(self):
        df = collect_all()
        return to_vtbda_vulnerabilities(df)


# ============================================================
# Debug local (hors VTBDA)
# ============================================================

def export_outputs(df: pd.DataFrame, out_csv: str = "docker_k8s_findings.csv", out_json: str = "docker_k8s_findings.json"):
    if df is None:
        df = pd.DataFrame()

    # JSON
    df_json = df.copy()
    df_json["cves"] = df_json["cves"].apply(lambda x: x if isinstance(x, list) else [])
    df_json.to_json(out_json, orient="records", force_ascii=False, indent=2)

    # CSV
    df_csv = df.copy()
    if "cves" in df_csv.columns:
        df_csv["cves"] = df_csv["cves"].apply(lambda x: ",".join(x) if isinstance(x, list) else "")
    df_csv.to_csv(out_csv, index=False, encoding="utf-8")

    print(f"Saved: {out_csv}, {out_json}")
    if not df.empty:
        cols = [c for c in ["ecosystem", "severity_guess", "risk_score_guess", "title"] if c in df.columns]
        print(df.head(10)[cols])


def run_once_debug():
    df = collect_all()
    export_outputs(df)


if __name__ == "__main__":
    # IMPORTANT: debug local uniquement.
    # Dans VTBDA, l’exécution est gérée par automation.py via DockerK8sCollector().run()
    run_once_debug()
