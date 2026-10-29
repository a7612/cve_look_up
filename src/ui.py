import re
from typing import Any, Dict, List, Optional
import textwrap

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.columns import Columns
    from rich import box
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


def render_cve_rich(data: Dict[str, Any]):
    """Hiển thị thông tin CVE theo layout giao diện rich."""
    cve_id = data.get("cve", "N/A")
    title = data.get("title") or "Không có tiêu đề (No Title)"
    cna = data.get("cna") or "N/A"
    published = data.get("published_date") or "N/A"
    modified = data.get("last_modified") or "N/A"

    # --- KHỐI BÊN TRÁI ---
    header_text = Text()
    header_text.append(f"Tra cứu: {cve_id}\n", style="bold cyan")
    header_text.append(title, style="bold white")
    header_panel = Panel(header_text, style="cyan", border_style="bold cyan", expand=True)

    meta_text = (
        f"[bold]CNA:[/bold] {cna}\n"
        f"[bold]Publish Date:[/bold] {published}\n"
        f"[bold]Last Modified:[/bold] {modified}"
    )
    meta_panel = Panel(meta_text, style="green", border_style="green", expand=True)

    left_column = Table.grid(expand=True)
    left_column.add_column()
    left_column.add_row(header_panel)
    left_column.add_row(meta_panel)

    # --- KHỐI BÊN PHẢI ---
    cwe_list = data.get("cwe") or []
    if cwe_list:
        cwe_strs = []
        seen_cwes = set()
        for c in cwe_list:
            cwe_id_val = c.get("id") or "CWE-Unknown"
            raw_name = c.get("name") or "Chưa rõ tên"
            cleaned_name = re.sub(r"^CWE-\d+\s*", "", raw_name, flags=re.IGNORECASE).strip()
            key = (cwe_id_val.upper(), cleaned_name.lower())
            if key not in seen_cwes:
                seen_cwes.add(key)
                cwe_strs.append(f"{cwe_id_val} - {cleaned_name}")
        cwe_display = "\n".join(cwe_strs)
    else:
        cwe_display = "[Không xác định CWE]"
    cwe_panel = Panel(Text(cwe_display, style="yellow"), style="yellow", border_style="yellow", expand=True)

    cvss = data.get("cvss") or {}
    s_40 = cvss.get("4.0") if cvss.get("4.0") is not None else "---"
    s_31 = cvss.get("3.1") if cvss.get("3.1") is not None else "---"
    s_30 = cvss.get("3.0") if cvss.get("3.0") is not None else "---"
    s_20 = cvss.get("2.0") if cvss.get("2.0") is not None else "---"

    metric_text = Text(justify="center")
    metric_text.append("[Metric / CVSS Base Score]\n", style="bold magenta")
    metric_text.append(f"4.0: {s_40}  |  3.1: {s_31}  |  3.0: {s_30}  |  2.0: {s_20}", style="bold white")
    metric_panel = Panel(metric_text, style="magenta", border_style="magenta", expand=True)

    right_column = Table.grid(expand=True)
    right_column.add_column()
    right_column.add_row(cwe_panel)
    right_column.add_row(metric_panel)

    # Ghép 2 cột trên
    top_grid = Table.grid(expand=True)
    top_grid.add_column(ratio=1)
    top_grid.add_column(ratio=1)
    top_grid.add_row(left_column, right_column)

    # Mô tả
    desc_en = data.get("description") or "Không có mô tả tiếng Anh."
    desc_vn = data.get("description_vn") or "Chưa có mô tả tiếng Việt (description_vn: null)."

    desc_en_panel = Panel(desc_en, title="Mô tả: EN", border_style="blue", style="white", expand=True)
    desc_vn_panel = Panel(desc_vn, title="Mô tả: VI", border_style="blue", style="white", expand=True)

    desc_table = Table.grid(expand=True)
    desc_table.add_column(ratio=1)
    desc_table.add_column(ratio=1)
    desc_table.add_row(desc_en_panel, desc_vn_panel)

    # Tham chiếu
    refs = data.get("references") or []
    if refs:
        ref_lines = []
        for r in refs[:8]:
            url = r.get("url", "")
            tags = ", ".join(r.get("tags", []))
            tags_str = f" [{tags}]" if tags else ""
            ref_lines.append(f"• {url}{tags_str}")
        if len(refs) > 8:
            ref_lines.append(f"... và {len(refs) - 8} liên kết khác.")
        ref_text = "\n".join(ref_lines)
    else:
        ref_text = "Không có liên kết tham chiếu."
    ref_panel = Panel(ref_text, title="Tham chiếu:", border_style="bright_black", style="white")

    layout_table = Table.grid(expand=True)
    layout_table.add_column()
    layout_table.add_row(top_grid)
    layout_table.add_row(desc_table)
    layout_table.add_row(ref_panel)

    outer_panel = Panel(layout_table, title="[bold white]THÔNG TIN CHI TIẾT CVE[/bold white]", border_style="bright_cyan")
    console.print(outer_panel)


def render_cve_plain(data: Dict[str, Any]):
    """Fallback text khi không có Rich."""
    cve_id = data.get("cve", "N/A")
    title = data.get("title") or "Không có tiêu đề (No Title)"
    cna = data.get("cna") or "N/A"
    published = data.get("published_date") or "N/A"
    modified = data.get("last_modified") or "N/A"

    print("+" + "-"*78 + "+")
    print(f"| Tra cứu: {cve_id}".ljust(79) + "|")
    print(f"| {title}".ljust(79) + "|")
    print("+" + "-"*78 + "+")

    cwe_list = data.get("cwe") or []
    cwe_str = ", ".join([f"{c.get('id')} ({c.get('name')})" for c in cwe_list]) if cwe_list else "Chưa rõ"
    print(f"| [CWE]: {cwe_str}".ljust(79) + "|")
    print("+" + "-"*78 + "+")

    print(f"| CNA: {cna} | Publish: {published} | Modified: {modified}".ljust(79) + "|")
    cvss = data.get("cvss") or {}
    print(f"| [Metric] 4.0: {cvss.get('4.0', '---')}, 3.1: {cvss.get('3.1', '---')}, 3.0: {cvss.get('3.0', '---')}, 2.0: {cvss.get('2.0', '---')}".ljust(79) + "|")
    print("+" + "-"*78 + "+")
    print(f"| [Mô tả: EN]: {data.get('description', '')[:70]}...".ljust(79) + "|")
    print(f"| [Mô tả: VI]: {data.get('description_vn', 'Chưa có')}".ljust(79) + "|")
    print("+" + "-"*78 + "+")


def display_cve(data: Dict[str, Any]):
    """Hiển thị chi tiết một CVE."""
    if RICH_AVAILABLE and console:
        render_cve_rich(data)
    else:
        render_cve_plain(data)


def display_cve_list(
    cve_items: List[Dict[str, Any]],
    title_text: Optional[str] = None,
    cwe_catalog: Optional[Dict[str, str]] = None
):
    """Hiển thị bảng danh sách các CVE và bảng thống kê CWE được đề cập."""
    if not cve_items:
        print_warning("Không có dữ liệu CVE nào phù hợp.")
        return

    banner_title = title_text or f"DANH SÁCH CVE HIỆN CÓ ({len(cve_items)} bản ghi)"

    # Tải cwe_catalog nếu không truyền vào
    if cwe_catalog is None:
        try:
            import json, os
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            cat_path = os.path.join(base_dir, "data", "cwe_catalog.json")
            if os.path.exists(cat_path):
                with open(cat_path, "r", encoding="utf-8") as f:
                    cwe_catalog = json.load(f)
            else:
                cwe_catalog = {}
        except Exception:
            cwe_catalog = {}

    # Gom các CWE được đề cập trong danh sách CVE này
    cwe_map = {}
    for item in cve_items:
        for c in item.get("cwe") or []:
            cwe_id = (c.get("id") or "").strip().upper()
            if not cwe_id or cwe_id == "N/A":
                continue

            # Chuẩn hóa key CWE (ví dụ: CWE-20, NVD-CWE-OTHER...)
            if not cwe_id.startswith("CWE-") and cwe_id.isdigit():
                cwe_id = f"CWE-{cwe_id}"

            # Ưu tiên lấy tên chuẩn từ cwe_catalog.json
            name = (cwe_catalog or {}).get(cwe_id)
            if not name:
                raw_name = (c.get("name") or "").strip()
                # Làm sạch tiền tố mã CWE nếu có trong raw_name
                clean_name = re.sub(r"^CWE-\d+\s*[:-]?\s*", "", raw_name, flags=re.IGNORECASE).strip()
                name = clean_name or "Chưa rõ tên"

            if cwe_id not in cwe_map:
                cwe_map[cwe_id] = name

    # Sắp xếp CWE theo số hiệu CWE
    def cwe_sort_key(cwe_id_str: str):
        nums = re.findall(r"\d+", cwe_id_str)
        return int(nums[0]) if nums else 999999

    sorted_cwes = sorted(cwe_map.items(), key=lambda x: cwe_sort_key(x[0]))

    if RICH_AVAILABLE and console:
        # Bảng 1: Danh sách CVE
        table_cve = Table(title=banner_title, border_style="cyan", box=box.ROUNDED, expand=True)
        table_cve.add_column("STT", style="dim", width=4, justify="center")
        table_cve.add_column("Mã CVE", style="bold cyan", width=15)
        table_cve.add_column("Tiêu đề", style="white")
        table_cve.add_column("Vị trí / Thư mục", style="green", width=18)

        for idx, item in enumerate(cve_items, start=1):
            title = item.get("title") or "(Không có tiêu đề)"
            table_cve.add_row(str(idx), item["cve"], title, item.get("location", ""))

        # Bảng 2: CWE được đề cập
        table_cwe = Table(
            title=f"CWE ĐƯỢC ĐỀ CẬP ({len(sorted_cwes)})",
            border_style="yellow",
            box=box.ROUNDED,
            expand=True
        )
        table_cwe.add_column("Mã CWE", style="bold yellow", width=10)
        table_cwe.add_column("Tên CWE", style="white")

        if sorted_cwes:
            for cwe_id, cwe_name in sorted_cwes:
                table_cwe.add_row(cwe_id, cwe_name)
        else:
            table_cwe.add_row("-", "(Không có CWE nào)")

        # Đặt 2 bảng cạnh nhau (cột tỉ lệ: 55% cho CVE, 45% cho CWE giúp Tên CWE rộng rãi, không bị co dòng)
        layout_grid = Table.grid(expand=True)
        layout_grid.add_column(ratio=55)
        layout_grid.add_column(ratio=45)
        layout_grid.add_row(table_cve, table_cwe)

        console.print(layout_grid)
    else:
        print(f"\n--- {banner_title} ---")
        for idx, item in enumerate(cve_items, start=1):
            title = item.get("title") or "(Không có tiêu đề)"
            print(f"{idx}. {item['cve']} | {item.get('location', '')} | {title[:45]}")

        print(f"\n--- CWE ĐƯỢC ĐỀ CẬP ({len(sorted_cwes)}) ---")
        for cwe_id, cwe_name in sorted_cwes:
            print(f"{cwe_id}: {cwe_name}")
        print("-" * 50)


# ========================================================
# CÁC MENU GIAO DIỆN RICH TEXT
# ========================================================

def print_main_menu():
    """Vẽ Menu chính."""
    if RICH_AVAILABLE and console:
        content = Text()
        content.append("  [1] ", style="bold cyan")
        content.append("Tra cứu CVE\n", style="bold white")
        content.append(" [00] ", style="bold yellow")
        content.append("Cài đặt (Settings)\n", style="bold white")
        content.append("  [0] ", style="bold red")
        content.append("Thoát", style="bold white")

        panel = Panel(
            content,
            title="[bold yellow]★★★★★[/bold yellow]",
            subtitle="[dim]Chọn một chức năng để tiếp tục[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
            width=50
        )
        console.print(panel)
    else:
        print("\n" + "="*45)
        print("====== HỆ THỐNG TRA CỨU CVE ======")
        print("1. Tra cứu CVE")
        print("00. Cài đặt (Settings)")
        print("0. Thoát")
        print("="*45)


def print_settings_banner(settings: Dict[str, Any]):
    """Vẽ giao diện cài đặt settings."""
    if RICH_AVAILABLE and console:
        content = Text()
        content.append("CẤU HÌNH HIỆN TẠI:\n", style="bold cyan")
        content.append("  [1] Giới hạn cào mỗi lần (crawl_max_per_one) : ", style="bold white")
        content.append(f"{settings.get('crawl_max_per_one', 500)}\n", style="bold green")
        content.append("  [2] Số luồng cào song song (crawl_threads)    : ", style="bold white")
        content.append(f"{settings.get('crawl_threads', 1)}\n\n", style="bold green")
        content.append("• Nhập số ", style="dim")
        content.append("[1]", style="bold yellow")
        content.append(" hoặc ", style="dim")
        content.append("[2]", style="bold yellow")
        content.append(" để đổi giá trị tương ứng.\n", style="dim")
        content.append("• Nhập ", style="dim")
        content.append("[0]", style="bold red")
        content.append(" hoặc ", style="dim")
        content.append("'b'", style="bold red")
        content.append(" để lưu và quay lại Menu chính.", style="dim")

        panel = Panel(
            content,
            title="[bold yellow]⚙️ CÀI ĐẶT HỆ THỐNG (SETTINGS)[/bold yellow]",
            border_style="yellow",
            box=box.ROUNDED,
            width=65
        )
        console.print(panel)
    else:
        print("\n" + "="*50)
        print("--- ⚙️ CÀI ĐẶT HỆ THỐNG (SETTINGS) ---")
        print(f"1. Giới hạn cào mỗi lần (crawl_max_per_one): {settings.get('crawl_max_per_one', 500)}")
        print(f"2. Số luồng song song (crawl_threads): {settings.get('crawl_threads', 1)}")
        print("Nhập 1 hoặc 2 để thay đổi. Nhập 0 hoặc b để quay lại.")
        print("="*50)


def print_search_menu_banner():
    """Vẽ banner chế độ Tra cứu CVE."""
    "Tôi tự chỉnh rồi nha, cứ như thế mà áp dụng"
    if RICH_AVAILABLE and console:
        content = Text()
        content.append("HƯỚNG DẪN:\n", style="cyan")

        content.append("• Tra cứu CVE: ", style="cyan")
        content.append("[Mã CVE]\n", style="cyan")
        content.append("\t• VD: CVE-2025-6115; CVE-2021-1111,...\n", style="dim")

        content.append("• Thêm CVE: ", style="cyan")
        content.append("+[Mã_CVE] hoặc +?[Từ_khóa]\n", style="bold green")
        content.append("\t• VD: +CVE-2025-6115; +CVE-2025-6115;CVE-2021-1111; +CVE-2025-6511->CVE-2025-6523; +?pillow\n", style="dim")

        content.append("• Danh sách:\n", style="cyan")

        content.append("• ?: ", style="bold yellow")
        content.append("Hiển thị tất cả các bản ghi\n", style="white")

        content.append("• ?*: ", style="bold yellow")
        content.append("Hiển thị tất cả các bản ghi có tiêu đề\n", style="white")

        content.append("• ?-*: ", style="bold yellow")
        content.append("Hiển thị tất cả các bản ghi không có tiêu đề\n", style="white")
        
        content.append("• ?keyword ", style="bold yellow")
        content.append("Hiển thị tất cả các bản ghi với các tiêu đề cùng với từ khóa\n", style="white")
        content.append("\t• VD: ?Pillow, ?Adobe...\n", style="dim")

        content.append("• Quay lại: ", style="bold white")
        content.append("'0'", style="bold red")
        content.append(" hoặc ", style="dim")
        content.append("'b'", style="bold red")

        panel = Panel(
            content,
            title="[bold cyan]🔍 1. TRA CỨU DỮ LIỆU CVE CÓ SẴN[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            width=100
        )
        console.print(panel)
    else:
        print("\n" + "="*50)
        print("--- 1. TRA CỨU DỮ LIỆU CVE CÓ SẴN ---")
        print("• Tra cứu: Nhập mã CVE (VD: CVE-2025-6115)")
        print("• Thêm mới: +Mã_CVE (VD: +CVE-2025-6115 hoặc +CVE-1;CVE-2)")
        print("• Danh sách: '?' (Tất cả) | '?*' (Có tiêu đề) | '?-*' (Không tiêu đề)")
        print("• Tìm kiếm: '?Từ_khóa' (VD: ?Pillow)")
        print("• Quay lại: '0' hoặc 'b'")
        print("="*50)


def print_success(msg: str):
    if RICH_AVAILABLE and console:
        console.print(f"[bold green][✓][/bold green] {msg}")
    else:
        print(f"[+] {msg}")


def print_error(msg: str):
    if RICH_AVAILABLE and console:
        console.print(f"[bold red][✗][/bold red] {msg}")
    else:
        print(f"[-] {msg}")


def print_warning(msg: str):
    if RICH_AVAILABLE and console:
        console.print(f"[bold yellow][!][/bold yellow] {msg}")
    else:
        print(f"[!] {msg}")


def print_info(msg: str):
    if RICH_AVAILABLE and console:
        console.print(f"[bold cyan][i][/bold cyan] {msg}")
    else:
        print(f"[i] {msg}")
