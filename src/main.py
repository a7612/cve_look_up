import json
import logging
import os
import re
import sys
from typing import Any, Dict, List, Optional
import requests
from ui import (
    display_cve,
    display_cve_list,
    print_main_menu,
    print_search_menu_banner,
    print_success,
    print_error,
    print_warning,
    print_info,
)

# Ensure utf-8 encoding for standard output on Windows console
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Base URLs
CVE_ORG_API_URL = "https://cveawg.mitre.org/api/cve"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_ZIP_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CVE-Collector/1.0"

# Global cache for CWE catalog (CWE-ID -> Name)
_CWE_CATALOG: Dict[str, str] = {}


def load_cwe_catalog(data_dir: str = "data") -> Dict[str, str]:
    """Load or download CWE catalog from MITRE."""
    global _CWE_CATALOG
    if _CWE_CATALOG:
        return _CWE_CATALOG

    catalog_path = os.path.join(data_dir, "cwe_catalog.json")
    if os.path.exists(catalog_path):
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                _CWE_CATALOG = json.load(f)
                return _CWE_CATALOG
        except Exception as e:
            logger.warning("Could not read local cwe_catalog.json: %s", e)

    # If not present or failed, fetch from MITRE
    import csv
    import io
    import zipfile
    try:
        logger.info("Downloading official CWE catalog from MITRE...")
        resp = requests.get(CWE_ZIP_URL, headers={"User-Agent": USER_AGENT}, timeout=20)
        if resp.status_code == 200:
            z = zipfile.ZipFile(io.BytesIO(resp.content))
            filename = z.namelist()[0]
            with z.open(filename) as f:
                reader = csv.reader(io.TextIOWrapper(f, "utf-8", errors="replace"))
                next(reader, None)  # Skip header
                for row in reader:
                    if row and len(row) >= 2:
                        cwe_num = row[0].strip()
                        cwe_name = row[1].strip()
                        _CWE_CATALOG[f"CWE-{cwe_num}"] = cwe_name
            _CWE_CATALOG["NVD-CWE-OTHER"] = "Other"
            _CWE_CATALOG["NVD-CWE-NOINFO"] = "Insufficient Information"
            os.makedirs(data_dir, exist_ok=True)
            with open(catalog_path, "w", encoding="utf-8") as f:
                json.dump(_CWE_CATALOG, f, indent=2, ensure_ascii=False)
            logger.info("Successfully cached %d CWE definitions to %s", len(_CWE_CATALOG), catalog_path)
    except Exception as e:
        logger.error("Failed to download CWE catalog: %s", e)

    return _CWE_CATALOG


def get_cwe_name(cwe_id: str, data_dir: str = "data") -> Optional[str]:
    catalog = load_cwe_catalog(data_dir=data_dir)
    return catalog.get(cwe_id.upper())


def fetch_cve_org(cve_id: str) -> Optional[Dict[str, Any]]:
    """Fetch CVE Record from cve.org / MITRE API."""
    url = f"{CVE_ORG_API_URL}/{cve_id}"
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        logger.warning("cve.org returned status %s for %s", resp.status_code, cve_id)
    except Exception as e:
        logger.error("Error fetching from cve.org for %s: %s", cve_id, e)
    return None


def fetch_nvd(cve_id: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetch CVE Record from NVD API 2.0."""
    url = f"{NVD_API_URL}?cveId={cve_id}"
    headers = {"User-Agent": USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve")
        logger.warning("NVD returned status %s for %s", resp.status_code, cve_id)
    except Exception as e:
        logger.error("Error fetching from NVD for %s: %s", cve_id, e)
    return None


def extract_cvss(cve_org_data: Optional[Dict[str, Any]], nvd_cve: Optional[Dict[str, Any]]) -> Dict[str, Optional[float]]:
    cvss = {
        "4.0": None,
        "3.1": None,
        "3.0": None,
        "2.0": None
    }

    # 1. Check cve.org metrics
    if cve_org_data:
        cna = cve_org_data.get("containers", {}).get("cna", {})
        for metric in cna.get("metrics", []):
            if not isinstance(metric, dict):
                continue
            for key, val in metric.items():
                if isinstance(val, dict):
                    ver = str(val.get("version", ""))
                    score = val.get("baseScore")
                    if score is not None:
                        try:
                            score_val = float(score)
                            if ver.startswith("4.0") and cvss["4.0"] is None:
                                cvss["4.0"] = score_val
                            elif ver.startswith("3.1") and cvss["3.1"] is None:
                                cvss["3.1"] = score_val
                            elif ver.startswith("3.0") and cvss["3.0"] is None:
                                cvss["3.0"] = score_val
                            elif ver.startswith("2.0") and cvss["2.0"] is None:
                                cvss["2.0"] = score_val
                        except (ValueError, TypeError):
                            pass

    # 2. Check NVD metrics (often primary source for official CVSS)
    if nvd_cve:
        metrics = nvd_cve.get("metrics", {})
        metric_mapping = [
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2", "2.0")
        ]
        for metric_key, version_key in metric_mapping:
            if cvss[version_key] is None and metric_key in metrics:
                metric_list = metrics[metric_key]
                if isinstance(metric_list, list) and len(metric_list) > 0:
                    primary_item = next((item for item in metric_list if item.get("type") == "Primary"), metric_list[0])
                    cvss_data = primary_item.get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    if score is not None:
                        try:
                            cvss[version_key] = float(score)
                        except (ValueError, TypeError):
                            pass

    return cvss


def extract_cwe(cve_org_data: Optional[Dict[str, Any]], nvd_cve: Optional[Dict[str, Any]], data_dir: str = "data") -> List[Dict[str, Optional[str]]]:
    cwes: List[Dict[str, Optional[str]]] = []
    seen = set()

    # From cve.org
    if cve_org_data:
        cna = cve_org_data.get("containers", {}).get("cna", {})
        for pt in cna.get("problemTypes", []) or []:
            for desc in pt.get("descriptions", []) or []:
                cwe_id = desc.get("cweId") or desc.get("description")
                if cwe_id and re.match(r"^CWE-\d+", str(cwe_id), re.IGNORECASE):
                    cwe_id_clean = cwe_id.upper()
                    key = (cwe_id_clean, "cve.org")
                    if key not in seen:
                        seen.add(key)
                        # Name from cve.org or fallback to official CWE catalog
                        raw_name = desc.get("description") if desc.get("cweId") else None
                        cwe_name = raw_name or get_cwe_name(cwe_id_clean, data_dir=data_dir)
                        cwes.append({
                            "id": cwe_id_clean,
                            "name": cwe_name,
                            "source": "cve.org"
                        })

    # From NVD
    if nvd_cve:
        for weakness in nvd_cve.get("weaknesses", []) or []:
            source = weakness.get("source") or "nvd.nist.gov"
            for desc in weakness.get("description", []) or []:
                cwe_id = desc.get("value")
                if cwe_id and (re.match(r"^CWE-\d+", str(cwe_id), re.IGNORECASE) or str(cwe_id).upper() == "NVD-CWE-OTHER" or str(cwe_id).upper() == "NVD-CWE-NOINFO"):
                    cwe_id_clean = cwe_id.upper()
                    key = (cwe_id_clean, source)
                    if key not in seen:
                        seen.add(key)
                        cwe_name = get_cwe_name(cwe_id_clean, data_dir=data_dir)
                        cwes.append({
                            "id": cwe_id_clean,
                            "name": cwe_name,
                            "source": source
                        })

    return cwes


def extract_references(cve_org_data: Optional[Dict[str, Any]], nvd_cve: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    refs: List[Dict[str, Any]] = []
    seen_urls = set()

    # From cve.org
    if cve_org_data:
        cna = cve_org_data.get("containers", {}).get("cna", {})
        for ref in cna.get("references", []) or []:
            url = ref.get("url")
            if url and url not in seen_urls:
                seen_urls.add(url)
                refs.append({
                    "url": url,
                    "source": "cve.org",
                    "tags": ref.get("tags", [])
                })

    # From NVD
    if nvd_cve:
        for ref in nvd_cve.get("references", []) or []:
            url = ref.get("url")
            if url:
                if url not in seen_urls:
                    seen_urls.add(url)
                    refs.append({
                        "url": url,
                        "source": ref.get("source") or "nvd.nist.gov",
                        "tags": ref.get("tags", [])
                    })
                else:
                    for existing_ref in refs:
                        if existing_ref["url"] == url:
                            existing_tags = set(existing_ref.get("tags", []))
                            new_tags = ref.get("tags", [])
                            existing_ref["tags"] = list(existing_tags.union(new_tags))
                            break

    return refs


def extract_description(cve_org_data: Optional[Dict[str, Any]], nvd_cve: Optional[Dict[str, Any]]) -> Optional[str]:
    # Try cve.org description first
    if cve_org_data:
        cna = cve_org_data.get("containers", {}).get("cna", {})
        descriptions = cna.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") in ("en", "en-US", "en-GB"):
                return d.get("value")
        if descriptions and descriptions[0].get("value"):
            return descriptions[0].get("value")

    # Fallback to NVD
    if nvd_cve:
        descriptions = nvd_cve.get("descriptions", [])
        for d in descriptions:
            if d.get("lang") == "en":
                return d.get("value")
        if descriptions and descriptions[0].get("value"):
            return descriptions[0].get("value")

    return None


def merge_cve_data(cve_id: str, cve_org_data: Optional[Dict[str, Any]], nvd_cve: Optional[Dict[str, Any]], data_dir: str = "data") -> Dict[str, Any]:
    cve_id_clean = cve_id.upper()

    title = None
    cna = None
    published_date = None
    last_modified = None

    if cve_org_data:
        cve_meta = cve_org_data.get("cveMetadata", {})
        cna_container = cve_org_data.get("containers", {}).get("cna", {})
        title = cna_container.get("title")
        cna = cve_meta.get("assignerShortName")
        published_date = cve_meta.get("datePublished")
        last_modified = cve_meta.get("dateUpdated")

    if nvd_cve:
        if not published_date:
            published_date = nvd_cve.get("published")
        if not last_modified:
            last_modified = nvd_cve.get("lastModified")
        if not cna:
            cna = nvd_cve.get("sourceIdentifier")

    return {
        "cve": cve_id_clean,
        "title": title,
        "cna": cna,
        "published_date": published_date,
        "last_modified": last_modified,
        "cvss": extract_cvss(cve_org_data, nvd_cve),
        "description": extract_description(cve_org_data, nvd_cve),
        "description_vn": None,
        "cwe": extract_cwe(cve_org_data, nvd_cve, data_dir=data_dir),
        "references": extract_references(cve_org_data, nvd_cve)
    }


def determine_save_paths(data_dir: str, cve_data: Dict[str, Any]) -> List[str]:
    cve_id = cve_data["cve"]
    # Save filenames in lowercase (e.g. cve-2025-6115.json)
    filename = f"{cve_id.lower()}.json"
    cwes = cve_data.get("cwe", [])

    paths = []
    if not cwes:
        paths.append(os.path.join(data_dir, "cwe-unknown", filename))
    else:
        saved_cwes = set()
        for item in cwes:
            cwe_id = (item.get("id") or "").strip().lower()
            if not cwe_id or cwe_id in ("nvd-cwe-noinfo", "unknown"):
                folder_name = "cwe-unknown"
                paths.append(os.path.join(data_dir, folder_name, filename))
                saved_cwes.add(folder_name)
            elif cwe_id == "nvd-cwe-other" or not re.match(r"^cwe-\d+$", cwe_id):
                folder_name = "cwe-other"
                if folder_name not in saved_cwes:
                    paths.append(os.path.join(data_dir, "cwe", folder_name, filename))
                    saved_cwes.add(folder_name)
            else:
                # Valid cwe-xx (lowercase)
                if cwe_id not in saved_cwes:
                    paths.append(os.path.join(data_dir, "cwe", cwe_id, filename))
                    saved_cwes.add(cwe_id)

    return paths


def save_cve(cve_data: Dict[str, Any], data_dir: str = "data") -> List[str]:
    target_paths = determine_save_paths(data_dir, cve_data)
    for path in target_paths:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cve_data, f, indent=4, ensure_ascii=False)
        logger.info("Saved %s to %s", cve_data["cve"], path)
    return target_paths


def crawl_cve(cve_id: str, data_dir: str = "data", nvd_api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    # Normalize cve_id format (e.g. "cve-2025-6115" -> "CVE-2025-6115")
    cve_id = cve_id.strip()
    if not cve_id.upper().startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"
    cve_id = cve_id.upper()

    logger.info("Starting crawl for %s...", cve_id)
    cve_org_data = fetch_cve_org(cve_id)
    nvd_cve = fetch_nvd(cve_id, api_key=nvd_api_key)

    if not cve_org_data and not nvd_cve:
        logger.error("Could not retrieve data for %s from both cve.org and NVD.", cve_id)
        return None

    merged = merge_cve_data(cve_id, cve_org_data, nvd_cve, data_dir=data_dir)
    save_cve(merged, data_dir=data_dir)
    return merged


def find_local_cve(cve_id: str, data_dir: str = "data") -> Optional[Dict[str, Any]]:
    """Tìm file dữ liệu CVE có sẵn trong thư mục data (quét cả cwe, cwe-unknown, records...)."""
    cve_id_clean = cve_id.strip()
    if not cve_id_clean.upper().startswith("CVE-"):
        cve_id_clean = f"CVE-{cve_id_clean}"
    target_filename = f"{cve_id_clean.lower()}.json"

    for root, _, files in os.walk(data_dir):
        for f in files:
            if f.lower() == target_filename:
                file_path = os.path.join(root, f)
                try:
                    with open(file_path, "r", encoding="utf-8") as json_f:
                        return json.load(json_f)
                except Exception as e:
                    logger.error("Lỗi khi đọc file %s: %s", file_path, e)
    return None


def list_local_cves(data_dir: str = "data") -> List[Dict[str, str]]:
    """Lấy danh sách tất cả các CVE hiện có trong thư mục data/ (không trùng lặp)."""
    found = {}
    for root, _, files in os.walk(data_dir):
        for f in files:
            if f.lower().startswith("cve-") and f.lower().endswith(".json"):
                file_path = os.path.join(root, f)
                rel_path = os.path.relpath(os.path.dirname(file_path), data_dir)
                cve_code = f[:-5].upper()
                if cve_code not in found:
                    title = ""
                    try:
                        with open(file_path, "r", encoding="utf-8") as jf:
                            d = json.load(jf)
                            title = d.get("title") or ""
                    except Exception:
                        pass
                    found[cve_code] = {
                        "cve": cve_code,
                        "title": title,
                        "location": rel_path
                    }
                else:
                    # Ghép thêm vị trí nếu một CVE nằm ở nhiều CWE
                    locs = found[cve_code]["location"].split(", ")
                    if rel_path not in locs:
                        found[cve_code]["location"] += f", {rel_path}"

    return sorted(found.values(), key=lambda x: x["cve"])


def search_cve_menu(data_dir: str):
    while True:
        print()
        print_search_menu_banner()
        user_input = input(">> Nhập lựa chọn hoặc mã CVE: ").strip()

        if user_input in ("0", "b", "B", "exit", "quit"):
            break

        if user_input == "?":
            cves = list_local_cves(data_dir)
            display_cve_list(cves, title_text=f"DANH SÁCH TẤT CẢ CVE ({len(cves)} bản ghi)")
            continue

        if user_input == "?*":
            cves = [c for c in list_local_cves(data_dir) if c.get("title") and c.get("title").strip()]
            display_cve_list(cves, title_text=f"DANH SÁCH CVE CÓ TIÊU ĐỀ ({len(cves)} bản ghi)")
            continue

        if user_input in ("?-*", "?!"):
            cves = [c for c in list_local_cves(data_dir) if not (c.get("title") and c.get("title").strip())]
            display_cve_list(cves, title_text=f"DANH SÁCH CVE KHÔNG CÓ TIÊU ĐỀ ({len(cves)} bản ghi)")
            continue

        if not user_input:
            print_warning("Vui lòng nhập mã CVE hợp lệ.")
            continue

        # Thêm dữ liệu CVE bằng cú pháp +[CVE-ID] hoặc nhiều mã phân cách bằng ';'
        if user_input.startswith("+"):
            raw_cves = user_input[1:].split(";")
            targets = []
            for item in raw_cves:
                cleaned = item.strip()
                # Bỏ ngoặc vuông nếu có
                if cleaned.startswith("[") and cleaned.endswith("]"):
                    cleaned = cleaned[1:-1].strip()
                # Xóa dấu '+' nếu lỡ người dùng gõ kiểu +CVE-1;+CVE-2
                if cleaned.startswith("+"):
                    cleaned = cleaned[1:].strip()
                if cleaned:
                    targets.append(cleaned)

            if not targets:
                print_warning("Vui lòng nhập ít nhất một mã CVE hợp lệ sau dấu '+'. Ví dụ: +CVE-2025-6115;CVE-2022-43089")
                continue

            success_cves = []
            failed_cves = []

            for idx, cve_target in enumerate(targets, start=1):
                if len(targets) > 1:
                    print_info(f"[{idx}/{len(targets)}] Đang cào dữ liệu cho {cve_target}...")
                else:
                    print_info(f"Đang cào dữ liệu cho {cve_target}...")

                result = crawl_cve(cve_target, data_dir=data_dir)
                if result:
                    print_success(f"Thành công! Đã lưu {result['cve']}.")
                    success_cves.append(result)
                else:
                    print_error(f"Thất bại: Không thể lấy dữ liệu cho '{cve_target}'.")
                    failed_cves.append(cve_target)

            # Nếu chỉ thêm 1 CVE thì render chi tiết, nếu nhiều thì tóm tắt và hiển thị danh sách
            if len(targets) == 1 and success_cves:
                display_cve(success_cves[0])
            elif len(targets) > 1:
                print()
                print_info(f"Kết quả xử lý: Thành công {len(success_cves)}/{len(targets)} CVE.")
                if failed_cves:
                    print_warning(f"Các CVE thất bại: {', '.join(failed_cves)}")
            continue

        cve_data = find_local_cve(user_input, data_dir=data_dir)
        if cve_data:
            display_cve(cve_data)
        else:
            print_error(f"Không tìm thấy dữ liệu có sẵn cho '{user_input}' trong thư mục data/.")
            print_info(f"Gợi ý: Nhập '+{user_input}' để tải về từ internet hoặc '?' để xem danh sách.")


def main_menu():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, "data")

    while True:
        print()
        print_main_menu()
        choice = input(">> Chọn chức năng: ").strip()

        if choice == "1":
            search_cve_menu(data_dir)            
        elif choice == "0":
            print_info("Tạm biệt!")
            sys.exit(0)
        else:
            print_warning("Lựa chọn không hợp lệ. Vui lòng chọn lại.")


if __name__ == "__main__":
    main_menu()
