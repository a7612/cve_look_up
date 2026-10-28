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


def display_cve_list(cve_items: List[Dict[str, str]]):
    """Hiển thị bảng danh sách các CVE hiện có."""
    if not cve_items:
        print_warning("Hiện chưa có dữ liệu CVE nào trong thư mục data/.")
        return

    if RICH_AVAILABLE and console:
        table = Table(title=f"DANH SÁCH CVE HIỆN CÓ ({len(cve_items)} bản ghi)", border_style="cyan", box=box.ROUNDED)
        table.add_column("STT", style="dim", width=6, justify="center")
        table.add_column("Mã CVE", style="bold cyan", width=18)
        table.add_column("Tiêu đề", style="white")
        table.add_column("Vị trí / Thư mục", style="green", width=25)

        for idx, item in enumerate(cve_items, start=1):
            title = item.get("title") or "(Không có tiêu đề)"
            table.add_row(str(idx), item["cve"], title, item.get("location", ""))

        console.print(table)
    else:
        print(f"\n--- DANH SÁCH CVE HIỆN CÓ ({len(cve_items)} bản ghi) ---")
        for idx, item in enumerate(cve_items, start=1):
            title = item.get("title") or "(Không có tiêu đề)"
            print(f"{idx}. {item['cve']} | {item.get('location', '')} | {title[:50]}")
        print("-" * 50)


# ========================================================
# CÁC MENU GIAO DIỆN RICH TEXT
# ========================================================

def print_main_menu():
    """Vẽ Menu chính."""
    if RICH_AVAILABLE and console:
        content = Text()
        content.append("  [1] ", style="bold cyan")
        content.append("Cập nhật dữ liệu\n", style="bold white")
        content.append("  [2] ", style="bold cyan")
        content.append("Tra cứu CVE\n", style="bold white")
        content.append("  [0] ", style="bold red")
        content.append("Thoát", style="bold white")

        panel = Panel(
            content,
            title="[bold yellow]★ HỆ THỐNG CRAWL & QUẢN LÝ CVE ★[/bold yellow]",
            subtitle="[dim]Chọn một chức năng để tiếp tục[/dim]",
            border_style="cyan",
            box=box.ROUNDED,
            width=50
        )
        console.print(panel)
    else:
        print("\n" + "="*45)
        print("====== HỆ THỐNG CRAWL CVE ======")
        print("1. Cập nhật dữ liệu")
        print("2. Tra cứu")
        print("0. Thoát")
        print("="*45)


def print_update_menu():
    """Vẽ Menu Cập nhật dữ liệu."""
    if RICH_AVAILABLE and console:
        content = Text()
        content.append("  [1] ", style="bold cyan")
        content.append("Thủ công (Nhập mã CVE cần cào)\n", style="bold white")
        content.append("  [0] ", style="bold red")
        content.append("Quay lại menu chính", style="bold white")

        panel = Panel(
            content,
            title="[bold green]► 1. CẬP NHẬT DỮ LIỆU[/bold green]",
            subtitle="[dim]Chọn phương thức cập nhật[/dim]",
            border_style="green",
            box=box.ROUNDED,
            width=50
        )
        console.print(panel)
    else:
        print("\n" + "="*45)
        print("--- 1. CẬP NHẬT DỮ LIỆU ---")
        print("1. Thủ công (nhập mã CVE)")
        print("0. Quay lại menu chính")
        print("="*45)


def print_manual_crawl_banner():
    """Vẽ banner chế độ Cào thủ công."""
    if RICH_AVAILABLE and console:
        content = Text()
        content.append("• Nhập mã CVE: ", style="bold white")
        content.append("CVE-2025-6115, cve-2026-99999...\n", style="cyan")
        content.append("• Nhập ", style="dim")
        content.append("'0'", style="bold red")
        content.append(" hoặc ", style="dim")
        content.append("'b'", style="bold red")
        content.append(" để quay lại menu trước.", style="dim")

        panel = Panel(
            content,
            title="[bold magenta]✦ THỦ CÔNG: CÀO DỮ LIỆU CVE ✦[/bold magenta]",
            border_style="magenta",
            box=box.ROUNDED,
            width=55
        )
        console.print(panel)
    else:
        print("\n" + "="*45)
        print("--- THỦ CÔNG: CÀO DỮ LIỆU CVE ---")
        print("Nhập mã CVE (VD: CVE-2025-6115 hoặc cve-2026-99999)")
        print("Nhập '0' hoặc 'b' để quay lại menu trước")
        print("="*45)


def print_search_menu_banner():
    """Vẽ banner chế độ Tra cứu CVE."""
    if RICH_AVAILABLE and console:
        content = Text()
        content.append("• Nhập mã CVE: ", style="bold white")
        content.append("CVE-2025-6115, CVE-2021-1111...\n", style="cyan")
        content.append("• Nhập ", style="dim")
        content.append("'?'", style="bold yellow")
        content.append(" để xem danh sách toàn bộ CVE hiện có.\n", style="yellow")
        content.append("• Nhập ", style="dim")
        content.append("'0'", style="bold red")
        content.append(" hoặc ", style="dim")
        content.append("'b'", style="bold red")
        content.append(" để quay lại menu chính.", style="dim")

        panel = Panel(
            content,
            title="[bold cyan]🔍 2. TRA CỨU DỮ LIỆU CVE CÓ SẴN[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
            width=55
        )
        console.print(panel)
    else:
        print("\n" + "="*45)
        print("--- 2. TRA CỨU DỮ LIỆU CVE CÓ SẴN ---")
        print("Nhập mã CVE (VD: CVE-2025-6115, CVE-2026-99999)")
        print("Nhập '?' để xem danh sách tất cả CVE hiện có")
        print("Nhập '0' hoặc 'b' để quay lại menu chính")
        print("="*45)


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
