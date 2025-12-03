import customtkinter as ctk
from tkinter import filedialog, messagebox, Menu
import threading
import sys
import io
import os
import subprocess
import platform
import zipfile
import tempfile
import datetime
from pathlib import Path

# --- CRITICAL FIX FOR PYINSTALLER + OLETOOLS ---
# Olevba tries to write to stdout/stderr. In --windowed mode, these are None.
# We redirect them to a dummy object to prevent the "no attribute flush" crash.
class NullWriter:
    def write(self, text): pass
    def flush(self): pass
    def isatty(self): return False

if sys.stdout is None: sys.stdout = NullWriter()
if sys.stderr is None: sys.stderr = NullWriter()

# Modular Imports
from gui.table import ForensicTable
from gui.report import ReportWindow
from utils.manual import MANUAL_TEXT
from utils.exporter import export_to_excel
from analyzers.batch import BatchAnalyzer
from core.loader import DocLoader

# Analyzers
from analyzers.origin import OriginAnalyzer
from analyzers.metadata import MetadataAnalyzer
from analyzers.rsid import RSIDAnalyzer
from analyzers.threats import ThreatScanner
from analyzers.macros import MacroScanner
from analyzers.media import MediaAnalyzer
from analyzers.authors import AuthorAnalyzer
from analyzers.extended import ExtendedAnalyzer
from analyzers.embeddings import EmbeddingAnalyzer
from analyzers.pptx_deep import PPTXDeepAnalyzer
from analyzers.exiftool_scan import ExifToolScanner

ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("blue")
MAX_UNCOMPRESSED_SIZE = 250 * 1024 * 1024 

class OfficeReconApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("OfficeRecon | Forensic Suite")
        self.geometry("1600x900")
        
        self.running = True
        self.log_entries = [] 
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._init_sidebar()
        self._init_table_area()
        self._init_statusbar()
        self.log_event("SYSTEM", "Ready.")
        
        # Check for ExifTool availability
        self._check_exiftool_availability()

    def on_close(self):
        self.running = False
        self.destroy()

    def _check_exiftool_availability(self):
        """Check if exiftool.exe and exiftool_files directory exist and show warning if missing."""
        exiftool_exe = Path("exiftool.exe")
        exiftool_dir = Path("exiftool_files")
        
        missing_items = []
        if not exiftool_exe.exists():
            missing_items.append("exiftool.exe")
        if not exiftool_dir.exists() or not exiftool_dir.is_dir():
            missing_items.append("exiftool_files directory")
        
        if missing_items:
            missing_text = "\n".join([f"• {item}" for item in missing_items])
            message = (f"ExifTool components are missing for best results:\n\n{missing_text}\n\n"
                      f"Please ensure exiftool.exe and the exiftool_files directory are in the same folder as OfficeRecon.exe.\n\n"
                      f"Note: When you download ExifTool, you need to rename it to exiftool.exe.")
            messagebox.showwarning("ExifTool Not Found", message)
            self.log_event("WARNING", f"ExifTool components missing: {', '.join(missing_items)}")

    def log_event(self, category, message):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_entries.append(f"[{ts}] [{category:<8}] {message}")

    def _init_sidebar(self):
        sb = ctk.CTkFrame(self, width=220, corner_radius=0)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_rowconfigure(9, weight=1)

        logo = ctk.CTkFrame(sb, fg_color="transparent")
        logo.grid(row=0, column=0, padx=20, pady=20, sticky="nw")
        ctk.CTkLabel(logo, text="Office", font=ctk.CTkFont(size=24, weight="bold"), text_color="#1F6AA5").pack(side="left")
        ctk.CTkLabel(logo, text="Recon", font=ctk.CTkFont(size=24, weight="bold"), text_color="white").pack(side="left")

        ctk.CTkLabel(sb, text="ACTIONS", text_color="#777", font=ctk.CTkFont(size=11, weight="bold")).grid(row=1, column=0, padx=20, pady=5, sticky="w")
        
        ctk.CTkButton(sb, text="LOAD FOLDER", command=self.load_batch_folder, font=ctk.CTkFont(weight="bold"), fg_color="#1F6AA5", hover_color="#144870").grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        ctk.CTkButton(sb, text="Load File", command=self.load_target_file, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE")).grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        ctk.CTkButton(sb, text="EXPORT XLSX", command=self.export_data_wrapper, font=ctk.CTkFont(weight="bold"), fg_color="#2E7D32", hover_color="#1B5E20").grid(row=4, column=0, padx=20, pady=20, sticky="ew")

        ctk.CTkLabel(sb, text="SCAN SETTINGS", text_color="#777", font=ctk.CTkFont(size=11, weight="bold")).grid(row=5, column=0, padx=20, pady=(20,5), sticky="w")
        self.deep_scan_var = ctk.StringVar(value="off")
        self.switch_deep = ctk.CTkSwitch(sb, text="Auto-Deep Scan", variable=self.deep_scan_var, onvalue="on", offvalue="off", font=("Segoe UI", 12))
        self.switch_deep.grid(row=6, column=0, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(sb, text="TOOLS", text_color="#777", font=ctk.CTkFont(size=11, weight="bold")).grid(row=7, column=0, padx=20, pady=(20,5), sticky="w")
        ctk.CTkButton(sb, text="VIEW LOGS", command=self.show_log_window, fg_color="#333", hover_color="#444").grid(row=8, column=0, padx=20, pady=5, sticky="ew")
        ctk.CTkButton(sb, text="Forensic Manual", command=self.show_manual, fg_color="transparent", text_color="gray").grid(row=10, column=0, padx=20, pady=20, sticky="ew")

    def _init_table_area(self):
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        container.grid_rowconfigure(1, weight=3)
        container.grid_rowconfigure(3, weight=1)
        container.grid_columnconfigure(0, weight=1)

        search_frame = ctk.CTkFrame(container, fg_color="transparent")
        search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ctk.CTkLabel(search_frame, text="FILTER:", font=ctk.CTkFont(size=12, weight="bold"), text_color="gray").pack(side="left", padx=(0, 10))
        self.search_var = ctk.StringVar()
        self.search_var.trace("w", self.on_search_change)
        self.entry_search = ctk.CTkEntry(search_frame, textvariable=self.search_var, placeholder_text="Type to search filenames, authors, threats...", height=35)
        self.entry_search.pack(side="left", fill="x", expand=True)

        cols = [
            {"key": "filename", "label": "File Name", "width": 250},
            {"key": "verdict", "label": "Remarks", "width": 100},
            {"key": "threats", "label": "Attention", "width": 300},
            {"key": "deep_output", "label": "Deep Scan Status", "width": 150}, 
            {"key": "md5", "label": "MD5 Hash", "width": 250},
            {"key": "is_duplicate", "label": "Duplicate", "width": 80}, 
            {"key": "full_path", "label": "Full Path", "width": 400},
            {"key": "hidden_text", "label": "Hidden", "width": 150},
            {"key": "author", "label": "Creator", "width": 150},
            {"key": "last_mod_by", "label": "Last Mod By", "width": 150},
            {"key": "printed", "label": "Last Printed", "width": 180},
            {"key": "meta_created", "label": "Meta Created", "width": 180},
            {"key": "meta_modified", "label": "Meta Mod", "width": 180},
            {"key": "title", "label": "Title", "width": 200},
            {"key": "leaked_user", "label": "Leaked User", "width": 150},
            {"key": "fs_modified", "label": "FS Modified", "width": 180},
            {"key": "fs_accessed", "label": "FS Access", "width": 180},
            {"key": "fs_created", "label": "FS Create", "width": 180},
            {"key": "zip_modified", "label": "Zip Date", "width": 180},
            {"key": "edit_time", "label": "Edit Time", "width": 100},
            {"key": "status", "label": "Status", "width": 100},
            {"key": "category", "label": "Category", "width": 100},
            {"key": "rsid_count", "label": "RSIDs", "width": 80},
            {"key": "template", "label": "Template", "width": 200},
            {"key": "generator", "label": "Software", "width": 200},
            {"key": "platform", "label": "OS", "width": 100},
            {"key": "rev_count", "label": "Rev", "width": 60},
            {"key": "pages", "label": "Pg", "width": 60},
            {"key": "slides", "label": "Sld", "width": 60},
            {"key": "words", "label": "Words", "width": 80},
            {"key": "media_count", "label": "Media", "width": 60},
            {"key": "size", "label": "Size", "width": 80}
        ]

        self.table = ForensicTable(container, cols, self.on_table_action, self.on_right_click)
        self.table.grid(row=1, column=0, sticky="nsew")

        self.details_frame = ctk.CTkFrame(container, fg_color="#232323", corner_radius=5)
        self.details_frame.grid(row=3, column=0, sticky="nsew", pady=(5, 0))
        ctk.CTkLabel(self.details_frame, text="EVIDENCE VIEWER (Select a row to inspect)", font=("Segoe UI", 11, "bold"), text_color="#777").pack(anchor="w", padx=10, pady=(5,0))
        self.details_box = ctk.CTkTextbox(self.details_frame, fg_color="#1e1e1e", text_color="#dcdcdc", font=("Consolas", 12))
        self.details_box.pack(fill="both", expand=True, padx=5, pady=5)
        self.details_box.configure(state="disabled")

    def _init_statusbar(self):
        self.status_var = ctk.StringVar(value="System Ready.")
        self.statusbar = ctk.CTkLabel(self, textvariable=self.status_var, anchor="w", fg_color="#1a1a1a", height=30, padx=20)
        self.statusbar.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.progress = ctk.CTkProgressBar(self, height=10, corner_radius=0, fg_color="#1a1a1a")
        self.progress.configure(mode="indeterminate")

    def safe_status(self, text):
        if self.running: self.after(0, lambda: self.status_var.set(text))

    def safe_table_add(self, row_data):
        if self.running: self.after(0, lambda: self.table.add_row(row_data))

    def safe_table_render(self):
        if self.running: self.after(0, lambda: self.table.filter(self.search_var.get()))

    def on_search_change(self, *args):
        self.table.filter(self.search_var.get())

    # --- ACTION HANDLER ---
    def on_table_action(self, row, is_single_click):
        if is_single_click:
            self.details_box.configure(state="normal")
            self.details_box.delete("1.0", "end")
            
            self.details_box.insert("end", "=== 1. IDENTITY & THREATS ===\n\n", "header")
            self._write_kv("Filename", row.get("filename"))
            self._write_kv("Full Path", row.get("full_path"))
            self._write_kv("MD5 Hash", row.get("md5"))
            self._write_kv("Verdict", row.get("verdict"))
            self._write_kv("Attention", row.get("threats"))
            if row.get("is_duplicate") == "X":
                self.details_box.insert("end", f"{'DUPLICATE':<20} : YES (Matches another file in this batch)\n", "alert")

            self.details_box.insert("end", "\n=== 2. METADATA & ORIGIN ===\n\n", "header")
            self._write_kv("Creator", row.get("author"))
            self._write_kv("Last Mod By", row.get("last_mod_by"))
            self._write_kv("Created (Meta)", row.get("meta_created"))
            self._write_kv("Modified (Meta)", row.get("meta_modified"))
            self._write_kv("Software", row.get("generator"))
            self._write_kv("OS Platform", row.get("platform"))
            
            deep_data = row.get('deep_output_raw', '')
            if deep_data:
                self.details_box.insert("end", "\n" + "="*60 + "\n", "sep")
                self.details_box.insert("end", "=== 3. DEEP FORENSIC REPORT ===\n", "header")
                self.details_box.insert("end", "="*60 + "\n\n", "sep")
                self.details_box.insert("end", deep_data)
            else:
                self.details_box.insert("end", "\n" + "="*60 + "\n", "sep")
                self.details_box.insert("end", "[INFO] Deep Scan data not loaded. Double-click file or enable 'Auto-Deep Scan'.", "info")

            self.details_box._textbox.tag_config("header", foreground="#1F6AA5", font=("Segoe UI", 12, "bold"))
            self.details_box._textbox.tag_config("sep", foreground="#555555")
            self.details_box._textbox.tag_config("alert", foreground="#ff5252")
            self.details_box._textbox.tag_config("info", foreground="#888888")
            self.details_box.configure(state="disabled")
        else:
            self.on_double_click(row)

    def _write_kv(self, key, value):
        if value: self.details_box.insert("end", f"{key:<20} : {value}\n")

    # --- LOADING ---
    def load_batch_folder(self):
        path = filedialog.askdirectory()
        if not path: return
        path = os.path.normpath(path)
        self.log_event("SELECT", f"Folder: {path}")
        self.status_var.set("Indexing file system... This may take time.")
        self.progress.grid(row=2, column=0, columnspan=2, sticky="ew"); self.progress.start()
        threading.Thread(target=self._discover_files, args=(path,)).start()

    def load_target_file(self):
        path = filedialog.askopenfilename()
        if path: 
            path = os.path.normpath(path)
            self.log_event("SELECT", f"File: {path}")
            self.run_scan([path])

    def _discover_files(self, path):
        files = []
        try:
            for root, _, filenames in os.walk(path):
                if not self.running: return 
                for f in filenames:
                    if f.lower().endswith(('.docx', '.odt', '.xlsx', '.pptx', '.zip')) and not f.startswith('~$'):
                        files.append(os.path.normpath(os.path.join(root, f)))
            self.log_event("INDEX", f"Found {len(files)} potential targets.")
            self.after(0, lambda: self.run_scan(files))
        except Exception as e:
            self.log_event("ERROR", f"File discovery failed: {e}")
            self.safe_status(f"Index Error: {e}")

    def run_scan(self, files):
        self.table.clear()
        self.progress.stop(); self.progress.grid_forget()
        self.status_var.set(f"Scanning {len(files)} files...")
        self.log_event("SCAN", f"Starting batch analysis on {len(files)} items.")
        threading.Thread(target=self._scan_thread, args=(files,), daemon=True).start()

    def _scan_thread(self, files):
        scanner = BatchAnalyzer()
        seen_hashes = set()
        hash_registry = {} 
        self.skipped_count = 0 
        self.indexed_count = 0
        deep_mode = self.deep_scan_var.get() == "on"
        
        for i, f in enumerate(files):
            if not self.running: break 
            self.safe_status(f"Processing {i+1}/{len(files)}: {os.path.basename(f)}")
            ext = os.path.splitext(f)[1].lower()
            if ext == ".zip": 
                added = self._process_zip(f, scanner, seen_hashes, hash_registry, deep_mode)
                if added == 0: self.skipped_count += 1
                else: self.indexed_count += added
            else: 
                if self._process_file(f, scanner, seen_hashes, hash_registry, deep_mode): self.indexed_count += 1
                else: self.skipped_count += 1
            if i % 10 == 0: self.safe_table_render()

        self.safe_table_render()
        final_msg = f"Scan Complete. {self.indexed_count} indexed. {self.skipped_count} skipped/empty."
        self.safe_status(final_msg)
        self.log_event("COMPLETE", final_msg)

    def _process_file(self, f, scanner, seen_hashes, hash_registry, deep_mode):
        try:
            d = scanner.analyze(f)
            d['full_path'] = f
            d['threats'] = ", ".join(d.get('threats', []))
            self._handle_duplication(d, hash_registry)
            if deep_mode:
                report_text = self._run_deep_logic_on_file(f, d)
                d['deep_output_raw'] = report_text 
                d['deep_output'] = report_text
            else:
                d['deep_output_raw'] = ""
                d['deep_output'] = ""
            self.safe_table_add(d)
            self.log_event("INDEXED", f"File: {os.path.basename(f)}")
            return True
        except Exception as e: 
            self.log_event("FAIL", f"{os.path.basename(f)}: {e}")
            return False

    def _process_zip(self, zip_path, scanner, seen_hashes, hash_registry, deep_mode):
        added_count = 0
        zip_name = os.path.basename(zip_path)
        try:
            with zipfile.ZipFile(zip_path, 'r') as z:
                all_infos = z.infolist()
                if not all_infos:
                    self.log_event("ZIP_SKIP", f"{zip_name}: Archive is empty.")
                    return 0
                valid_found = False
                for file_info in all_infos:
                    if not self.running: return 0
                    inner_name = file_info.filename
                    if os.path.splitext(inner_name)[1].lower() in ['.docx', '.xlsx', '.pptx', '.docm', '.odt']:
                        valid_found = True
                        if file_info.file_size > MAX_UNCOMPRESSED_SIZE: 
                            self.log_event("ZIP_SKIP", f"Skipped huge file {inner_name}")
                            continue
                        try:
                            with tempfile.TemporaryDirectory() as tmp:
                                extracted = z.extract(file_info, path=tmp)
                                d = scanner.analyze(extracted)
                                d['filename'] = inner_name
                                d['full_path'] = f"{zip_path} [>>] {inner_name}"
                                d['threats'] = ", ".join(d.get('threats', []))
                                self._handle_duplication(d, hash_registry)
                                if deep_mode:
                                    report_text = self._run_deep_logic_on_file(extracted, d)
                                    d['deep_output_raw'] = report_text
                                    d['deep_output'] = report_text
                                else:
                                    d['deep_output_raw'] = ""
                                    d['deep_output'] = ""
                                self.safe_table_add(d)
                                added_count += 1
                                self.log_event("INDEXED", f"Extracted: {inner_name} (Source: {zip_name})")
                        except Exception as e:
                            self.log_event("ZIP_ERR", f"Failed extract {inner_name}: {e}")
                if not valid_found: self.log_event("ZIP_SKIP", f"{zip_name}: No indexable Office documents found.")
            return added_count
        except Exception as e: 
            self.log_event("ZIP_FAIL", f"Could not read {zip_name}: {e}")
            return 0

    def _run_deep_logic_on_file(self, filepath, row_data):
        try:
            cap = io.StringIO(); old_stdout = sys.stdout; sys.stdout = cap
            l = DocLoader(filepath)
            if l.load():
                def safe(cls): 
                    try: cls(l).run()
                    except: pass
                safe(MediaAnalyzer); safe(MetadataAnalyzer); safe(MacroScanner); safe(ExtendedAnalyzer); safe(EmbeddingAnalyzer)
                if l.file_type == 'docx': safe(OriginAnalyzer); safe(RSIDAnalyzer); safe(ThreatScanner); safe(AuthorAnalyzer)
                elif l.file_type == 'pptx': safe(PPTXDeepAnalyzer)
                try: ExifToolScanner(filepath).run()
                except: pass
                l.close()
            sys.stdout = old_stdout
            return cap.getvalue()
        except: return "[Error running Deep Scan]"
        finally: sys.stdout = sys.__stdout__

    def _handle_duplication(self, d, hash_registry):
        md5 = d.get('md5', "")
        if md5 and md5 != "Error":
            if md5 in hash_registry:
                d['is_duplicate'] = "X"
                for prev_row in hash_registry[md5]: prev_row['is_duplicate'] = "X"
                hash_registry[md5].append(d)
            else:
                d['is_duplicate'] = ""
                hash_registry[md5] = [d]
        else: d['is_duplicate'] = ""

    def show_log_window(self):
        win = ctk.CTkToplevel(self); win.title("Activity Log"); win.geometry("800x600"); win.attributes("-topmost", True)
        txt = ctk.CTkTextbox(win, font=("Consolas", 12), text_color="#dcdcdc", fg_color="#1e1e1e"); txt.pack(fill="both", expand=True, padx=10, pady=10)
        for entry in self.log_entries:
            txt.insert("end", entry + "\n")
            if "ERROR" in entry or "FAIL" in entry: 
                line_idx = str(int(txt.index("end-1c").split('.')[0]))
                txt._textbox.tag_add("err", f"{line_idx}.0", f"{line_idx}.end"); txt._textbox.tag_config("err", foreground="#ff5252")
            elif "ARCHIVE" in entry:
                line_idx = str(int(txt.index("end-1c").split('.')[0]))
                txt._textbox.tag_add("arch", f"{line_idx}.0", f"{line_idx}.end"); txt._textbox.tag_config("arch", foreground="#00A0D6")
        txt.configure(state="disabled")

    def on_double_click(self, row):
        path = row['full_path']
        if " [>>] " in path: self._show_loading_zip(row['filename'], path)
        else: self._show_loading(row['filename'], path)

    def on_right_click(self, event, row, idx):
        m = Menu(self, tearoff=0)
        m.add_command(label="Deep Scan", command=lambda: self.on_double_click(row))
        m.add_command(label="Open Location", command=lambda: self.open_loc(row['full_path']))
        m.tk_popup(event.x_root, event.y_root)

    def open_loc(self, path):
        if " [>>] " in path: path = path.split(" [>>] ")[0]
        if os.path.exists(path):
            if platform.system() == "Windows": subprocess.Popen(f'explorer /select,"{os.path.normpath(path)}"')

    def _show_loading(self, title, path):
        win = ctk.CTkToplevel(self); win.geometry("400x150"); win.title("Deep Scan"); win.attributes("-topmost", True)
        ctk.CTkLabel(win, text="Scanning...", font=("Segoe UI", 16)).pack(pady=40)
        threading.Thread(target=self._deep_scan_thread, args=(win, title, path)).start()

    def _show_loading_zip(self, title, complex_path):
        win = ctk.CTkToplevel(self); win.geometry("400x150"); win.title("Extracting"); win.attributes("-topmost", True)
        ctk.CTkLabel(win, text="Extracting...", font=("Segoe UI", 16)).pack(pady=40)
        parts = complex_path.split(" [>>] ")
        def extract():
            with tempfile.TemporaryDirectory() as tmp:
                with zipfile.ZipFile(parts[0], 'r') as z:
                    extracted = z.extract(parts[1], path=tmp)
                    self._deep_scan_thread(win, title, extracted)
        threading.Thread(target=extract).start()

    def _deep_scan_thread(self, popup, title, filepath):
        cap_main = io.StringIO(); cap_auth = io.StringIO(); original = sys.stdout
        try:
            sys.stdout = cap_main
            d = BatchAnalyzer().analyze(filepath)
            print(f"=== DOSSIER: {d['filename']} ===\nRemarks: {d['verdict']} | Attention: {', '.join(d['threats'])}\nMD5: {d['md5']}\n{'='*60}\n")
            try: ExifToolScanner(filepath).run()
            except: pass
            l = DocLoader(filepath)
            if l.load():
                safe = lambda c: c(l).run()
                safe(MediaAnalyzer); safe(MetadataAnalyzer); safe(MacroScanner); safe(ExtendedAnalyzer); safe(EmbeddingAnalyzer)
                if l.file_type == 'docx': safe(OriginAnalyzer); safe(RSIDAnalyzer); safe(ThreatScanner); safe(AuthorAnalyzer)
                elif l.file_type == 'pptx': safe(PPTXDeepAnalyzer)
            sys.stdout = cap_auth
            if l.zip_ref and l.file_type == 'docx': safe(RSIDAnalyzer); safe(AuthorAnalyzer)
            l.close()
        except: pass
        finally: sys.stdout = sys.__stdout__
        self.after(0, lambda: [popup.destroy(), ReportWindow(self, title, cap_main.getvalue(), cap_auth.getvalue(), filepath)])

    def export_data_wrapper(self):
        missing_count = sum(1 for r in self.table.table_data if not r.get('deep_output_raw'))
        if missing_count > 0:
            if messagebox.askyesno("Incomplete Data", f"{missing_count} files have not been Deep Scanned.\nScan now for full report?"):
                self._run_missing_deep_scans()
                return
        export_to_excel(self.table.table_data, self.table.columns)

    def _run_missing_deep_scans(self):
        self.status_var.set("Running Deep Scans for Export...")
        self.progress.grid(row=2, column=0, columnspan=2, sticky="ew"); self.progress.start()
        threading.Thread(target=self._deep_scan_filler_thread, daemon=True).start()

    def _deep_scan_filler_thread(self):
        total = len(self.table.table_data)
        for i, row in enumerate(self.table.table_data):
            if not self.running: break
            if row.get('deep_output_raw'): continue
            self.safe_status(f"Deep Scanning for Export: {i+1}/{total} - {row['filename']}")
            try:
                path = row['full_path']
                if " [>>] " in path:
                    parts = path.split(" [>>] ")
                    with tempfile.TemporaryDirectory() as tmp:
                        with zipfile.ZipFile(parts[0], 'r') as z:
                            extracted = z.extract(parts[1], path=tmp)
                            report_text = self._run_deep_logic_on_file(extracted, row)
                else:
                    report_text = self._run_deep_logic_on_file(path, row)
                row['deep_output_raw'] = report_text; row['deep_output'] = report_text
            except Exception as e: row['deep_output'] = f"[Scan Failed: {e}]"
        self.after(0, lambda: [self.progress.stop(), self.progress.grid_forget(), self.status_var.set("Ready."), export_to_excel(self.table.table_data, self.table.columns)])

    def show_manual(self):
        w = ctk.CTkToplevel(self); w.geometry("800x600"); w.attributes("-topmost", True)
        t = ctk.CTkTextbox(w, font=("Segoe UI", 14)); t.pack(fill="both", expand=True); t.insert("end", MANUAL_TEXT); t.configure(state="disabled")

if __name__ == "__main__":
    app = OfficeReconApp()
    app.mainloop()