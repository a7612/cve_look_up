import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional
import threading
import requests
from ui import (
    display_cve,
    display_cve_list,
    print_main_menu,
    print_settings_banner,
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
CVE_ORG_SEARCH_URL = "https://www.cve.org/restapiv1/search"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CWE_ZIP_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CVE-Collector/1.0"

# Global cache for CWE catalog (CWE-ID -> Name)
_CWE_CATALOG: Dict[str, str] = {}


def load_settings(base_dir: Optional[str] = None) -> Dict[str, Any]:
    """Tải cấu hình từ settings.json."""
    default_settings = {
        "crawl_max_per_one": 500,
        "crawl_threads": 5
    }
    if not base_dir:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    settings_path = os.path.join(base_dir, "settings.json")
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                default_settings.update(loaded)
        except Exception as e:
            logger.warning("Không thể đọc settings.json: %s. Dùng cấu hình mặc định.", e)
    return default_settings


def save_settings(settings: Dict[str, Any], base_dir: Optional[str] = None):
    """Lưu cấu hình vào file settings.json."""
    if not base_dir:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    settings_path = os.path.join(base_dir, "settings.json")
    try:
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error("Không thể ghi settings.json: %s", e)
        return False


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


def search_cve_org_by_keyword(keyword: str, max_results: Optional[int] = None) -> tuple[int, List[str]]:
    """Tìm kiếm danh sách CVE ID từ cve.org theo từ khóa."""
    headers = {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json"
    }

    # Lấy thông tin tổng số lượng trước
    init_payload = {
        "query": keyword,
        "from": 0,
        "size": 1
    }
    try:
        resp = requests.post(CVE_ORG_SEARCH_URL, json=init_payload, headers=headers, timeout=15)
        if resp.status_code != 200:
            return 0, []
        data = resp.json()
        total_count = data.get("resultsTotal", 0)
    except Exception as e:
        logger.error("Lỗi khi tìm kiếm CVE trên cve.org: %s", e)
        return 0, []

    if total_count == 0:
        return 0, []

    target_count = total_count if max_results is None else min(total_count, max_results)
    cve_ids = []
    page_size = 100
    current_from = 0

    while len(cve_ids) < target_count:
        fetch_size = min(page_size, target_count - len(cve_ids))
        payload = {
            "query": keyword,
            "from": current_from,
            "size": fetch_size
        }
        try:
            r = requests.post(CVE_ORG_SEARCH_URL, json=payload, headers=headers, timeout=20)
            if r.status_code != 200:
                break
            res_json = r.json()
            items = res_json.get("data", [])
            if not items:
                break
            for item in items:
                cve_id = item.get("_id") or item.get("_source", {}).get("cveMetadata", {}).get("cveId")
                if cve_id and cve_id not in cve_ids:
                    cve_ids.append(cve_id)
            current_from += len(items)
        except Exception as e:
            logger.error("Lỗi khi tải kết quả trang tìm kiếm: %s", e)
            break

    return total_count, cve_ids


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


def list_local_cves(data_dir: str = "data") -> List[Dict[str, Any]]:
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
                    cwe_list = []
                    try:
                        with open(file_path, "r", encoding="utf-8") as jf:
                            d = json.load(jf)
                            title = d.get("title") or ""
                            cwe_list = d.get("cwe") or []
                    except Exception:
                        pass
                    found[cve_code] = {
                        "cve": cve_code,
                        "title": title,
                        "location": rel_path,
                        "cwe": cwe_list,
                    }
                else:
                    # Ghép thêm vị trí nếu một CVE nằm ở nhiều CWE
                    locs = found[cve_code]["location"].split(", ")
                    if rel_path not in locs:
                        found[cve_code]["location"] += f", {rel_path}"

    return sorted(found.values(), key=lambda x: x["cve"])


def search_cve_menu(data_dir: str, base_dir: Optional[str] = None):
    cwe_catalog = load_cwe_catalog(data_dir=data_dir)

    while True:
        print()
        print_search_menu_banner()
        user_input = input(">> Nhập lựa chọn hoặc mã CVE: ").strip()

        if user_input in ("0", "b", "B", "exit", "quit"):
            break

        if user_input == "?":
            cves = list_local_cves(data_dir)
            display_cve_list(cves, title_text=f"DANH SÁCH TẤT CẢ CVE ({len(cves)} bản ghi)", cwe_catalog=cwe_catalog)
            continue

        if user_input == "?*":
            cves = [c for c in list_local_cves(data_dir) if c.get("title") and c.get("title").strip()]
            display_cve_list(cves, title_text=f"DANH SÁCH CVE CÓ TIÊU ĐỀ ({len(cves)} bản ghi)", cwe_catalog=cwe_catalog)
            continue

        if user_input in ("?-*", "?!"):
            cves = [c for c in list_local_cves(data_dir) if not (c.get("title") and c.get("title").strip())]
            display_cve_list(cves, title_text=f"DANH SÁCH CVE KHÔNG CÓ TIÊU ĐỀ ({len(cves)} bản ghi)", cwe_catalog=cwe_catalog)
            continue

        if user_input.startswith("?"):
            keyword = user_input[1:].strip()
            # Bỏ ngoặc vuông nếu người dùng nhập dạng ?[keyword]
            if keyword.startswith("[") and keyword.endswith("]"):
                keyword = keyword[1:-1].strip()

            if not keyword:
                cves = list_local_cves(data_dir)
                display_cve_list(cves, title_text=f"DANH SÁCH TẤT CẢ CVE ({len(cves)} bản ghi)", cwe_catalog=cwe_catalog)
            else:
                keyword_lower = keyword.lower()
                cves = [
                    c for c in list_local_cves(data_dir)
                    if c.get("title") and keyword_lower in c.get("title", "").lower()
                ]
                display_cve_list(cves, title_text=f"DANH SÁCH CVE KHỚP TỪ KHÓA '{keyword}' ({len(cves)} bản ghi)", cwe_catalog=cwe_catalog)
            continue

        if not user_input:
            print_warning("Vui lòng nhập mã CVE hợp lệ.")
            continue

        # Thêm dữ liệu CVE bằng cú pháp:
        # 1. Từ khóa cve.org: +?[keyword]
        # 2. Range: +CVE-2025-6511->CVE-2025-6523
        # 3. Danh sách: +CVE-2025-6115;CVE-2021-1111
        if user_input.startswith("+"):
            content_str = user_input[1:].strip()

            # TH: Tìm kiếm trên cve.org bằng +?keyword
            if content_str.startswith("?"):
                keyword = content_str[1:].strip()
                if keyword.startswith("[") and keyword.endswith("]"):
                    keyword = keyword[1:-1].strip()

                if not keyword:
                    print_warning("Vui lòng nhập từ khóa sau dấu '+?'. Ví dụ: +?pillow")
                    continue

                print_info(f"Đang kiểm tra số lượng kết quả cho từ khóa '{keyword}' trên cve.org...")
                # Lấy trước total_count bằng cách gọi thử
                total_found, _ = search_cve_org_by_keyword(keyword, max_results=1)
                print_info(f"Tìm thấy tổng cộng {total_found} CVE kết quả cho '{keyword}'.")

                if total_found == 0:
                    print_warning(f"Không có CVE nào khớp với từ khóa '{keyword}' trên cve.org.")
                    continue

                user_crawl_choice = input(">> Bạn muốn crawl bao nhiêu dữ liệu? (nhấn Enter: 500, nhập 'all': tất cả): ").strip().lower()

                if user_crawl_choice == "all":
                    limit_fetch = None
                elif user_crawl_choice == "":
                    limit_fetch = 500
                else:
                    try:
                        limit_fetch = int(user_crawl_choice)
                        if limit_fetch <= 0:
                            print_warning("Số lượng không hợp lệ. Mặc định lấy 500.")
                            limit_fetch = 500
                    except ValueError:
                        print_warning("Giá trị không hợp lệ. Mặc định lấy 500.")
                        limit_fetch = 500

                print_info(f"Đang lấy danh sách mã CVE từ cve.org (tối đa: {'Toàn bộ' if limit_fetch is None else limit_fetch})...")
                _, targets = search_cve_org_by_keyword(keyword, max_results=limit_fetch)

            # Kiểm tra cú pháp range ->
            elif "->" in content_str:
                parts = content_str.split("->", 1)
                left_raw = parts[0].strip().strip("[]").upper()
                right_raw = parts[1].strip().strip("[]").upper()

                match_left = re.match(r"^CVE-(\d{4})-(\d+)$", left_raw, re.IGNORECASE)
                match_right = re.match(r"^CVE-(\d{4})-(\d+)$", right_raw, re.IGNORECASE)

                if not match_left or not match_right:
                    print_error("Cú pháp range không hợp lệ! Vui lòng nhập dạng: +CVE-YYYY-LOW->CVE-YYYY-HIGH")
                    continue

                year_left, seq_left = int(match_left.group(1)), int(match_left.group(2))
                year_right, seq_right = int(match_right.group(1)), int(match_right.group(2))

                # TH3: Khác năm -> Chặn
                if year_left != year_right:
                    print_error("Lượng dữ liệu quá lớn, không thể crawl được")
                    continue

                # TH1 & TH2: Tự động sắp xếp low -> high
                low_seq = min(seq_left, seq_right)
                high_seq = max(seq_left, seq_right)
                year = year_left

                total_items = high_seq - low_seq + 1
                settings = load_settings(base_dir=base_dir)
                max_per_one = int(settings.get("crawl_max_per_one", 500))

                if total_items > max_per_one:
                    print_error(f"Lượng dữ liệu quá lớn ({total_items} CVEs), không thể crawl được (tối đa {max_per_one} trong một lần).")
                    high_seq = low_seq + max_per_one - 1
                    print_info(f"Hệ thống sẽ tự động giới hạn cào {max_per_one} CVE đầu tiên: CVE-{year}-{low_seq} -> CVE-{year}-{high_seq}")

                targets = [f"CVE-{year}-{s}" for s in range(low_seq, high_seq + 1)]
            else:
                # Phân tách theo dấu ';'
                raw_cves = content_str.split(";")
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
                print_warning("Vui lòng nhập mã CVE hợp lệ. Ví dụ: +CVE-2025-6115 hoặc +CVE-2025-6511->CVE-2025-6523")
                continue

            settings = load_settings(base_dir=base_dir)
            num_threads = max(1, int(settings.get("crawl_threads", 1)))

            success_cves = []
            failed_cves = []
            print_lock = threading.Lock()
            completed_count = 0
            total_targets = len(targets)

            def process_cve(cve_code: str):
                nonlocal completed_count
                result = crawl_cve(cve_code, data_dir=data_dir)
                with print_lock:
                    completed_count += 1
                    if result:
                        if total_targets > 1:
                            print_success(f"[{completed_count}/{total_targets}] Thành công! Đã lưu {result['cve']}.")
                        else:
                            print_success(f"Thành công! Đã lưu {result['cve']}.")
                    else:
                        if total_targets > 1:
                            print_error(f"[{completed_count}/{total_targets}] Thất bại: Không thể lấy dữ liệu cho '{cve_code}'.")
                        else:
                            print_error(f"Thất bại: Không thể lấy dữ liệu cho '{cve_code}'.")
                return result, cve_code

            if num_threads > 1 and total_targets > 1:
                print_info(f"Đang cào {total_targets} CVE với {num_threads} luồng song song...")
                with ThreadPoolExecutor(max_workers=num_threads) as executor:
                    futures = [executor.submit(process_cve, t) for t in targets]
                    for f in as_completed(futures):
                        res, cve_code = f.result()
                        if res:
                            success_cves.append(res)
                        else:
                            failed_cves.append(cve_code)
            else:
                for cve_target in targets:
                    res, cve_code = process_cve(cve_target)
                    if res:
                        success_cves.append(res)
                    else:
                        failed_cves.append(cve_code)

            # Nếu chỉ thêm 1 CVE thì render chi tiết, nếu nhiều thì tóm tắt
            if len(targets) == 1 and success_cves:
                display_cve(success_cves[0])
            elif len(targets) > 1:
                print()
                print_info(f"Kết quả xử lý: Thành công {len(success_cves)}/{len(targets)} CVE.")
                if failed_cves:
                    print_warning(f"Các CVE thất bại: {', '.join(failed_cves[:20])}{' ...' if len(failed_cves) > 20 else ''}")
            continue

        cve_data = find_local_cve(user_input, data_dir=data_dir)
        if cve_data:
            display_cve(cve_data)
        else:
            print_error(f"Không tìm thấy dữ liệu có sẵn cho '{user_input}' trong thư mục data/.")
            print_info(f"Gợi ý: Nhập '+{user_input}' để tải về từ internet hoặc '?' để xem danh sách.")


def settings_menu(base_dir: str):
    """Menu chỉnh sửa tham số cấu hình settings.json."""
    while True:
        settings = load_settings(base_dir=base_dir)
        print()
        print_settings_banner(settings)
        choice = input(">> Chọn cài đặt cần đổi [1/2] hoặc '0' để quay lại: ").strip()

        if choice in ("0", "b", "B", "exit", "quit"):
            break

        if choice == "1":
            cur_val = settings.get("crawl_max_per_one", 500)
            val_str = input(f">> Nhập giá trị mới cho crawl_max_per_one (hiện tại: {cur_val}): ").strip()
            if not val_str:
                continue
            try:
                val = int(val_str)
                if val <= 0:
                    print_warning("Giá trị phải lớn hơn 0.")
                    continue
                settings["crawl_max_per_one"] = val
                if save_settings(settings, base_dir=base_dir):
                    print_success(f"Đã cập nhật crawl_max_per_one = {val}")
            except ValueError:
                print_error("Vui lòng nhập một số nguyên hợp lệ.")

        elif choice == "2":
            cur_val = settings.get("crawl_threads", 5)
            val_str = input(f">> Nhập số luồng crawl_threads (hiện tại: {cur_val}, khuyến nghị 1-20): ").strip()
            if not val_str:
                continue
            try:
                val = int(val_str)
                if val <= 0:
                    print_warning("Số luồng phải lớn hơn 0.")
                    continue
                settings["crawl_threads"] = val
                if save_settings(settings, base_dir=base_dir):
                    print_success(f"Đã cập nhật crawl_threads = {val}")
            except ValueError:
                print_error("Vui lòng nhập một số nguyên hợp lệ.")
        else:
            print_warning("Lựa chọn không hợp lệ. Vui lòng chọn 1, 2 hoặc 0.")


def main_menu():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, "data")

    while True:
        print()
        print_main_menu()
        choice = input(">> Chọn chức năng: ").strip()

        if choice == "1":
            search_cve_menu(data_dir, base_dir=base_dir)            
        elif choice in ("00", "settings"):
            settings_menu(base_dir)
        elif choice == "0":
            print_info("Tạm biệt!")
            sys.exit(0)
        else:
            print_warning("Lựa chọn không hợp lệ. Vui lòng chọn lại.")


if __name__ == "__main__":
    main_menu()
