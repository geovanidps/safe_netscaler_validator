#!/usr/bin/env python3
"""
safe_netscaler_validator_v2.py

Versão melhorada: coleta passiva, heurísticas de versão, relatório com evidências, score,
e geração de relatório PDF. NÃO-EXPLORATÓRIO por padrão (dry-run). Para executar requisições
reais em laboratório autorizado, passe --confirm.

Uso (dry-run por padrão):
  python3 safe_netscaler_validator_v2.py --target https://example.com --endpoints /vpn/index.html --output report_v2.json

Para executar requisições reais (lab autorizado):
  python3 safe_netscaler_validator_v2.py --target https://example.com --endpoints /vpn/index.html --output report_v2.json --confirm

Gera também um PDF com o mesmo prefixo do JSON (ex.: report_v2.pdf).
"""

from __future__ import annotations
import argparse
import json
import logging
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter, Retry
from requests.exceptions import RequestException

# PDF generation
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

# ---------- Config ----------
DEFAULT_ENDPOINTS = ["/", "/vpn/index.html", "/vpn/"]
SUSPICIOUS_PATTERNS = [
    r"uname -a",
    r"nsconfig",
    r"====CONF:",
    r"====KEY:",
    r"curl -sf",
    r"root@",
    r"command not found",
    r"LogonPoint",
    r"NetScaler",
    r"Citrix"
]
ADMIN_ENDPOINTS = ["/nsconfig/", "/var/", "/cgi-bin/", "/admin/", "/nsconfig/ns.conf", "/nsconfig/ssl/"]
VERSION_HINT_PATTERNS = [
    r"NetScaler\s+(\d+\.\d+(\.\d+)?)",
    r"Citrix\s+NetScaler\s+(\d+\.\d+)",
    r"ns\sversion[:=]\s*([0-9\.]+)",
    r"ADC\s+(\d+\.\d+)"
]

# ---------- Data classes ----------
@dataclass
class ProbeResult:
    endpoint: str
    url: str
    head: Dict[str, Any]
    get: Dict[str, Any]
    header_findings: List[Dict[str, Any]]
    text_indicators: List[Dict[str, Any]]
    timing: Dict[str, Any]
    admin_checks: List[Dict[str, Any]]
    version_hints: List[str]

@dataclass
class Report:
    target: str
    timestamp: str
    tls: Optional[Dict[str, Any]]
    endpoints: List[ProbeResult]
    evidences: List[Dict[str, Any]]
    confidence: Dict[str, Any]
    recommended_next_steps: List[str]
    notes: List[str]

# ---------- Utilities ----------
def setup_logging(level: str = "INFO"):
    levelno = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(level=levelno, format="%(asctime)s %(levelname)s %(message)s")

def get_tls_info(hostname: str, port: int = 443, timeout: int = 5) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                info['subject'] = cert.get('subject')
                info['issuer'] = cert.get('issuer')
                info['notBefore'] = cert.get('notBefore')
                info['notAfter'] = cert.get('notAfter')
                info['serialNumber'] = cert.get('serialNumber')
    except Exception as e:
        info['error'] = str(e)
    return info

def create_session(timeout: int = 10, retries: int = 2, backoff_factor: float = 0.3) -> requests.Session:
    s = requests.Session()
    retries_obj = Retry(total=retries, backoff_factor=backoff_factor,
                        status_forcelist=[429, 500, 502, 503, 504],
                        allowed_methods=["HEAD", "GET"])
    s.mount("https://", HTTPAdapter(max_retries=retries_obj))
    s.mount("http://", HTTPAdapter(max_retries=retries_obj))
    s.headers.update({"User-Agent": "SafeNetScalerValidator/2.0", "Accept-Encoding": "identity"})
    return s

def safe_request(session: requests.Session, url: str, method: str = "GET", timeout: int = 10) -> Dict[str, Any]:
    try:
        headers = {"User-Agent": session.headers.get("User-Agent"), "Accept": "*/*", "Accept-Encoding": "identity"}
        if method == "HEAD":
            r = session.head(url, timeout=timeout, allow_redirects=True, headers=headers)
        else:
            r = session.get(url, timeout=timeout, allow_redirects=True, headers=headers)
        return {
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "url": r.url,
            "content_snippet": (r.text[:4000] if r.text else ""),
            "length": len(r.content),
            "elapsed_ms": int(r.elapsed.total_seconds() * 1000)
        }
    except RequestException as e:
        return {"error": str(e)}

def analyze_headers(headers: Dict[str, Any], version_patterns: Dict[str, str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    server = headers.get("Server") or headers.get("server") or ""
    if server:
        findings.append({"type": "server_header", "value": server})
        for comp, pat in version_patterns.items():
            try:
                if re.search(pat, server, re.IGNORECASE):
                    findings.append({"type": "version_banner_match", "component": comp, "banner": server})
            except re.error:
                continue
    for h in ("X-Citrix-Via", "X-Netscaler-HostId", "X-Via-NSCOPI", "Set-Cookie", "X-Frame-Options"):
        if headers.get(h):
            findings.append({"type": "header_leak", "header": h, "value": headers.get(h)})
    return findings

def detect_text_indicators(snippet: str, patterns: List[str]) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for p in patterns:
        try:
            if re.search(p, snippet, re.IGNORECASE):
                matches.append({"pattern": p, "matched": True})
        except re.error:
            continue
    return matches

def extract_version_hints(snippet: str) -> List[str]:
    hints: List[str] = []
    for p in VERSION_HINT_PATTERNS:
        try:
            m = re.search(p, snippet, re.IGNORECASE)
            if m:
                hints.append(m.group(0))
        except re.error:
            continue
    return hints

def timing_probe(session: requests.Session, url: str, attempts: int = 3, timeout: int = 10, pause: float = 0.5) -> Dict[str, Any]:
    times: List[Optional[float]] = []
    for _ in range(attempts):
        start = time.time()
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":session.headers.get("User-Agent"), "Accept-Encoding":"identity"})
            elapsed = time.time() - start
            times.append(elapsed)
        except Exception:
            times.append(None)
        time.sleep(pause)
    valid = [t for t in times if t is not None]
    stats = {"attempts": attempts, "raw": times, "min": min(valid) if valid else None, "max": max(valid) if valid else None, "avg": (sum(valid)/len(valid)) if valid else None}
    return stats

def check_admin_endpoints(session: requests.Session, base: str, endpoints: List[str], timeout: int = 6) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for ep in endpoints:
        url = urljoin(base, ep)
        try:
            r = session.head(url, timeout=timeout, allow_redirects=True, headers={"User-Agent":session.headers.get("User-Agent")})
            results.append({"endpoint": ep, "url": url, "status_code": r.status_code, "accessible": r.status_code < 400})
        except Exception as e:
            results.append({"endpoint": ep, "url": url, "error": str(e)})
    return results

def compute_confidence(evidences: List[Dict[str, Any]], version_hints: List[str]) -> Dict[str, Any]:
    score = 0
    reasons: List[str] = []
    for e in evidences:
        t = e.get("type")
        detail = e.get("detail", {})
        if t == "server_header" and "NetScaler" in (detail.get("value","") or ""):
            score += 30
            reasons.append("Server header mentions NetScaler")
        if t == "header_leak" and detail.get("header","").lower().startswith("set-cookie") and "NSC_ESNS" in (detail.get("value","") or ""):
            score += 30
            reasons.append("NSC_ESNS cookie present")
        if t == "header_leak" and detail.get("header","").lower().startswith("x-via-nscopi"):
            score += 10
            reasons.append("X-Via-NSCOPI header present")
        if t == "text_indicator" and "NetScaler" in (detail.get("pattern","") or ""):
            score += 20
            reasons.append("HTML/text contains NetScaler strings")
    if version_hints:
        score += 20
        reasons.append("Version hints found in content")
    score = min(score, 100)
    level = "low"
    if score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    return {"score": score, "level": level, "reasons": reasons}

# ---------- PDF generation ----------
def generate_pdf_report(report_obj: Dict[str, Any], pdf_path: str):
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    title = f"NetScaler Validation Report - {report_obj.get('target')}"
    story.append(Paragraph(title, styles['Title']))
    story.append(Spacer(1, 12))
    meta = f"Generated: {report_obj.get('timestamp')}"
    story.append(Paragraph(meta, styles['Normal']))
    story.append(Spacer(1, 12))

    # Confidence summary
    conf = report_obj.get("confidence", {})
    conf_text = f"Confidence score: {conf.get('score', 'N/A')} - Level: {conf.get('level', 'N/A')}"
    story.append(Paragraph(conf_text, styles['Heading2']))
    if conf.get("reasons"):
        for r in conf.get("reasons"):
            story.append(Paragraph(f"- {r}", styles['Normal']))
    story.append(Spacer(1, 12))

    # TLS
    story.append(Paragraph("TLS / Certificate", styles['Heading2']))
    tls = report_obj.get("tls") or {}
    if tls.get("error"):
        story.append(Paragraph(f"TLS error: {tls.get('error')}", styles['Normal']))
    else:
        subj = tls.get("subject")
        issuer = tls.get("issuer")
        story.append(Paragraph(f"Subject: {subj}", styles['Normal']))
        story.append(Paragraph(f"Issuer: {issuer}", styles['Normal']))
        story.append(Paragraph(f"Valid from: {tls.get('notBefore')} to {tls.get('notAfter')}", styles['Normal']))
    story.append(Spacer(1, 12))

    # Endpoints table summary
    story.append(Paragraph("Endpoints Summary", styles['Heading2']))
    table_data = [["Endpoint", "Status (GET)", "Server Header", "Indicators", "Timing (ms)"]]
    for ep in report_obj.get("endpoints", []):
        get = ep.get("get", {})
        status = get.get("status_code", "err")
        server = ""
        for hf in ep.get("header_findings", []):
            if hf.get("type") == "server_header":
                server = hf.get("value")
        indicators = ", ".join([ti.get("pattern") for ti in ep.get("text_indicators", [])]) or "-"
        timing = ep.get("timing", {}).get("avg")
        table_data.append([ep.get("endpoint"), str(status), server or "-", indicators, str(timing)])
    t = Table(table_data, colWidths=[120, 80, 120, 120, 80])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.lightgrey),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    # Evidences and recommendations
    story.append(Paragraph("Evidences", styles['Heading2']))
    for ev in report_obj.get("evidences", []):
        story.append(Paragraph(json.dumps(ev, ensure_ascii=False), styles['Code']))
    story.append(Spacer(1, 12))

    story.append(Paragraph("Recommended Next Steps", styles['Heading2']))
    for step in report_obj.get("recommended_next_steps", []):
        story.append(Paragraph(f"- {step}", styles['Normal']))

    story.append(Spacer(1, 12))
    # Final verdict (heuristic)
    level = report_obj.get("confidence", {}).get("level", "unknown")
    verdict = "UNKNOWN"
    if level == "high":
        verdict = "POSSIBLE PRESENCE OF NETSCALER - FURTHER VERSION CHECK REQUIRED (HIGH CONFIDENCE)"
    elif level == "medium":
        verdict = "PRESENCE LIKELY - INVESTIGATE VERSION (MEDIUM CONFIDENCE)"
    elif level == "low":
        verdict = "INSUFFICIENT EVIDENCE OF NETSCALER PRESENCE (LOW CONFIDENCE)"
    story.append(Paragraph("Heuristic Verdict", styles['Heading2']))
    story.append(Paragraph(verdict, styles['Normal']))

    doc.build(story)

# ---------- Main logic ----------
def run_checks(target: str, endpoints: List[str], timeout: int, attempts: int, version_patterns: Dict[str,str],
               admin_endpoints: List[str], dry_run: bool, session: Optional[requests.Session]) -> Report:
    parsed = urlparse(target)
    if not parsed.scheme:
        raise ValueError("Inclua o esquema (https:// ou http://) no target.")

    if session is None:
        session = create_session(timeout=timeout)

    report = Report(target=target, timestamp=datetime.utcnow().isoformat()+"Z", tls=None, endpoints=[], evidences=[], confidence={}, recommended_next_steps=[], notes=[])

    if parsed.scheme == "https":
        host = parsed.hostname
        port = parsed.port or 443
        report.tls = get_tls_info(host, port, timeout=timeout)

    for ep in endpoints:
        ep = ep if ep.startswith("/") else "/" + ep
        url = urljoin(target, ep)
        if dry_run:
            head = {"note": "dry-run; request not executed"}
            get = {"note": "dry-run; request not executed"}
            timing = {"note": "dry-run"}
            header_findings = []
            text_indicators = []
            admin_checks = []
            version_hints = []
        else:
            head = safe_request(session, url, method="HEAD", timeout=timeout)
            get = safe_request(session, url, method="GET", timeout=timeout)
            header_findings = analyze_headers(get.get("headers", {}) if isinstance(get, dict) else {}, version_patterns)
            text_indicators = detect_text_indicators(get.get("content_snippet","") if isinstance(get, dict) else "", SUSPICIOUS_PATTERNS)
            version_hints = extract_version_hints(get.get("content_snippet","") if isinstance(get, dict) else "")
            timing = timing_probe(session, url, attempts=attempts, timeout=timeout)
            admin_checks = check_admin_endpoints(session, target, admin_endpoints, timeout=6)
        evidences_local = []
        for h in header_findings:
            evidences_local.append({"type": h.get("type"), "detail": h})
        for t in text_indicators:
            evidences_local.append({"type": "text_indicator", "detail": t})
        for v in version_hints:
            evidences_local.append({"type": "version_hint", "detail": v})
        report.evidences.extend(evidences_local)
        pr = ProbeResult(endpoint=ep, url=url, head=head, get=get, header_findings=header_findings, text_indicators=text_indicators, timing=timing, admin_checks=admin_checks, version_hints=version_hints)
        report.endpoints.append(pr)

    version_hints_all = [v for e in report.endpoints for v in e.version_hints]
    report.confidence = compute_confidence(report.evidences, version_hints_all)
    report.recommended_next_steps = [
        "Correlacionar evidências com logs do NetScaler (audit, ns.log, AAA logs).",
        "Identificar versão exata do NetScaler/ADC via console/GUI/SSH (em ambiente autorizado).",
        "Comparar versão com bulletins oficiais da Citrix para CVE-2026-88771 e CVE-2026-88778.",
        "Se versão vulnerável for confirmada, aplicar patches oficiais imediatamente.",
        "Se necessário, executar pentest autorizado em ambiente isolado para confirmação."
    ]
    if report.confidence.get("level") in ("medium", "high"):
        report.notes.append("Evidências indicam presença de NetScaler. Investigar versão e logs para confirmar vulnerabilidade.")
    else:
        report.notes.append("Evidências insuficientes para afirmar presença/vulnerabilidade com alta confiança.")
    return report

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="Safe NetScaler CVE validator v2 (non-exploitative) with PDF output.")
    p.add_argument("--target", required=True, help="Target URL (include scheme)")
    p.add_argument("--endpoints", default=",".join(DEFAULT_ENDPOINTS), help="Comma-separated endpoints")
    p.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")
    p.add_argument("--attempts", type=int, default=2, help="Timing probe attempts")
    p.add_argument("--output", default="report_v2.json", help="Output JSON report")
    p.add_argument("--version-patterns", help="JSON mapping component->regex for banner matching")
    p.add_argument("--confirm", action="store_true", help="Confirm execution outside dry-run (required to disable dry-run)")
    p.add_argument("--dry-run", action="store_true", default=True, help="Do not perform network requests (default)")
    p.add_argument("--log-level", default="INFO", help="Logging level")
    return p.parse_args()

def main():
    args = parse_args()
    setup_logging(level=args.log_level)
    dry_run = args.dry_run and not args.confirm
    if dry_run:
        logging.info("Modo dry-run ativo. Nenhuma requisição de rede será executada.")
    else:
        logging.warning("Modo ativo: requisições de rede serão executadas. Certifique-se de ter autorização por escrito.")
    try:
        version_patterns = json.loads(args.version_patterns) if args.version_patterns else {"citrix": r"Citrix|NetScaler|ADC"}
    except Exception:
        logging.error("version-patterns deve ser JSON válido.")
        return
    endpoints = [e if e.startswith("/") else "/"+e for e in args.endpoints.split(",") if e.strip()]
    session = None
    if not dry_run:
        session = create_session(timeout=args.timeout)
    report = run_checks(target=args.target, endpoints=endpoints, timeout=args.timeout, attempts=args.attempts, version_patterns=version_patterns, admin_endpoints=ADMIN_ENDPOINTS, dry_run=dry_run, session=session)
    out = {
        "target": report.target,
        "timestamp": report.timestamp,
        "tls": report.tls,
        "endpoints": [asdict(e) for e in report.endpoints],
        "evidences": report.evidences,
        "confidence": report.confidence,
        "recommended_next_steps": report.recommended_next_steps,
        "notes": report.notes
    }
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    logging.info(f"Relatório JSON salvo em {args.output}")
    # Generate PDF
    pdf_path = args.output.rsplit(".", 1)[0] + ".pdf"
    try:
        generate_pdf_report(out, pdf_path)
        logging.info(f"Relatório PDF salvo em {pdf_path}")
    except Exception as e:
        logging.error(f"Falha ao gerar PDF: {e}")

if __name__ == "__main__":
    main()
