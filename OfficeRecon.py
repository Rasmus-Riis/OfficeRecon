import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
import threading
import sys
import io
import os
import re
import subprocess
import platform
import csv  # <--- [ADDED] For Export
from PIL import Image, ImageTk 

# Import Content & Core
from utils.manual import MANUAL_TEXT
from analyzers.batch import BatchAnalyzer
from core.loader import DocLoader

# Import Analyzers
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

# --- CONFIGURATION ---
ctk.set_appearance_mode("Dark")  
ctk.set_default_color_theme("blue")

class AdvancedDocRecon(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("OfficeRecon | Forensic Suite")
        self.geometry("1600x900")
        
        # Data
        self.path_map = {}     
        self.report_cache = {} 
        self.image_ref = None 

        # Layout Configuration
        self.grid_columnconfigure(1, weight=1) # Main content expands
        self.grid_rowconfigure(0, weight=1)

        # UI Components
        self.create_sidebar()
        self.create_main_area()
        self.create_statusbar()
        
        # Apply Table Styles
        self.apply_treeview_style()

    def create_sidebar(self):
        """Left navigation sidebar."""
        self.sidebar_frame = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(5, weight=1) # Push help to bottom

        # LOGO
        self.logo_frame = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.logo_frame.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="nw")
        
        # "Office" (Blue)
        ctk.CTkLabel(self.logo_frame, text="Office", font=ctk.CTkFont(size=24, weight="bold"), 
                     text_color="#1F6AA5").pack(side="left")
        # "Recon" (White)
        ctk.CTkLabel(self.logo_frame, text="Recon", font=ctk.CTkFont(size=24, weight="bold"), 
                     text_color="white").pack(side="left")

        # TITLE LABEL
        ctk.CTkLabel(self.sidebar_frame, text="FORENSIC ACTIONS", anchor="w", 
                     text_color="#777777", font=ctk.CTkFont(size=11, weight="bold")).grid(row=1, column=0, padx=20, pady=(10, 5), sticky="w")

        # BUTTONS
        self.btn_folder = ctk.CTkButton(self.sidebar_frame, text="LOAD FOLDER", command=self.load_batch_folder,
                                        font=ctk.CTkFont(weight="bold"), height=40,
                                        fg_color="#1F6AA5", hover_color="#144870")
        self.btn_folder.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        self.btn_file = ctk.CTkButton(self.sidebar_frame, text="Load Single File", command=self.load_target_file,
                                      fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.btn_file.grid(row=3, column=0, padx=20, pady=10, sticky="ew")

        # EXPORT BUTTON (Green for Excel)
        self.btn_export = ctk.CTkButton(self.sidebar_frame, text="EXPORT CSV", command=self.export_data,
                                        font=ctk.CTkFont(weight="bold"), height=40,
                                        fg_color="#2E7D32", hover_color="#1B5E20") # Excel Green
        self.btn_export.grid(row=4, column=0, padx=20, pady=(20, 10), sticky="ew")

        # BOTTOM BUTTONS
        self.btn_help = ctk.CTkButton(self.sidebar_frame, text="Forensic Manual", command=self.show_manual,
                                      fg_color="transparent", text_color="gray")
        self.btn_help.grid(row=6, column=0, padx=20, pady=20, sticky="ew")

    def create_main_area(self):
        """Right side area containing the table."""
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=(10, 0))
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        # Treeview Columns
        cols = (
            "filename", "verdict", "threats", "md5", "hidden_text",
            "author", "last_mod", "printed", "meta_created", "meta_modified", 
            "title", "leaked_user", "fs_modified", "fs_accessed", "fs_created", 
            "zip_modified", "edit_time", "status", "category", 
            "rsid_count", "template", "app", "platform", "rev", "pages", "slides", "words", "media", "size"
        )

        # Treeview Widget
        self.tree = ttk.Treeview(self.main_frame, columns=cols, show="headings", selectmode="browse")
        
        # Scrollbars (Using standard because they link to Treeview better)
        vsb = ttk.Scrollbar(self.main_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(self.main_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        # Configure Headers
        headers = {
            "filename": "File Name", "verdict": "Verdict", "threats": "Threats", "md5": "MD5 Hash",
            "hidden_text": "Hidden Content", "author": "Creator", "last_mod": "Last Saved By", "printed": "Last Printed",
            "meta_created": "Created", "meta_modified": "Modified", "title": "Title", "leaked_user": "Embedded User",
            "fs_modified": "FS Mod", "fs_accessed": "FS Acc", "fs_created": "FS Cre", "zip_modified": "Zip Date",
            "edit_time": "Edit Time", "status": "Status", "category": "Category", "rsid_count": "RSIDs",
            "template": "Template", "app": "App", "platform": "OS", "rev": "Rev", "pages": "Pg", 
            "slides": "Sld", "words": "Words", "media": "Media", "size": "Size"
        }
        
        for col in cols:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self.sort_col(c, False))
            w = 100
            if col == "filename": w = 350
            if col == "threats": w = 250
            if col == "md5": w = 220
            if col in ["author", "last_mod"]: w = 150
            if "fs_" in col or "meta_" in col: w = 160 
            if col in ["rev", "pages", "media", "rsid_count", "slides"]: w = 60
            self.tree.column(col, width=w, anchor="w" if col in ["filename", "threats", "md5"] else "center")

        # Binds
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def create_statusbar(self):
        self.status_var = ctk.StringVar(value="System Ready. Load a folder to begin.")
        self.statusbar = ctk.CTkLabel(self, textvariable=self.status_var, anchor="w", 
                                      fg_color="#222222", height=30, padx=20, font=("Consolas", 10))
        self.statusbar.grid(row=1, column=0, columnspan=2, sticky="ew")

    def apply_treeview_style(self):
        """Forces the standard tkinter Treeview to look like CustomTkinter."""
        style = ttk.Style()
        style.theme_use("clam")
        
        # Dark Theme Colors
        bg_color = "#2b2b2b"
        fg_color = "white"
        header_bg = "#1f1f1f"
        selected_bg = "#1F6AA5"
        
        style.configure("Treeview", 
                        background=bg_color, 
                        foreground=fg_color, 
                        fieldbackground=bg_color,
                        borderwidth=0, 
                        rowheight=35,
                        font=("Segoe UI", 10))
        
        style.configure("Treeview.Heading", 
                        background=header_bg, 
                        foreground="white", 
                        relief="flat",
                        font=("Segoe UI", 10, "bold"))
        
        style.map("Treeview", background=[('selected', selected_bg)])
        style.map("Treeview.Heading", background=[('active', "#333333")])

    def create_context_menu(self):
        self.context_menu = tk.Menu(self, tearoff=0, bg="#2b2b2b", fg="white")
        self.context_menu.add_command(label="Open Containing Folder", command=self.open_file_location)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Deep Scan & Report", command=lambda: self.on_double_click(None))

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def open_file_location(self):
        item = self.tree.selection()
        if not item: return
        item_id = item[0]
        file_path = self.path_map.get(item_id)
        if not file_path or not os.path.exists(file_path): return
        try:
            if platform.system() == "Windows": subprocess.Popen(f'explorer /select,"{os.path.normpath(file_path)}"')
            elif platform.system() == "Darwin": subprocess.run(["open", "-R", file_path])
            else: subprocess.run(["xdg-open", os.path.dirname(file_path)])
        except: pass

    # --- LOADING LOGIC ---
    def load_target_file(self):
        path = filedialog.askopenfilename(filetypes=[("Documents", "*.docx *.odt *.xlsx *.pptx")])
        if path: self.run_scan([path], clear=True)

    def load_batch_folder(self):
        path = filedialog.askdirectory()
        if path:
            files = []
            for root, _, filenames in os.walk(path):
                for f in filenames:
                    if f.lower().endswith(('.docx', '.odt', '.xlsx', '.pptx')) and not f.startswith('~$'):
                        files.append(os.path.join(root, f))
            self.run_scan(files, clear=True)

    def run_scan(self, file_list, clear=False):
        if clear:
            self.tree.delete(*self.tree.get_children())
            self.report_cache = {}
            self.path_map = {}
        threading.Thread(target=self._execution_loop, args=(file_list,)).start()

    def _execution_loop(self, files):
        total = len(files)
        timed_out_files = []
        TIMEOUT_SECONDS = 5  

        for i, filepath in enumerate(files):
            filename = os.path.basename(filepath)
            self.status_var.set(f"Analyzing {i+1}/{total}: {filename}...")

            result_container = {"data": None}
            def target_scan():
                try:
                    scanner = BatchAnalyzer()
                    result_container["data"] = scanner.analyze(filepath)
                except: pass

            t = threading.Thread(target=target_scan)
            t.daemon = True
            t.start()
            t.join(timeout=TIMEOUT_SECONDS)

            if t.is_alive():
                print(f"[TIMEOUT] Abandoning stuck file: {filename}")
                timed_out_files.append(filepath) 
            else:
                d = result_container["data"]
                if d:
                    threat_str = ", ".join(d.get('threats', []))
                    row = (
                        d['filename'], d['verdict'], threat_str, d['md5'], d['hidden_text'], 
                        d['author'], d['last_mod_by'], d['printed'], 
                        d['meta_created'], d['meta_modified'],
                        d['title'], d['leaked_user'],
                        d['fs_modified'], d['fs_accessed'], d['fs_created'], 
                        d['zip_modified'], 
                        d['edit_time'], d['status'], d['category'],
                        d['rsid_count'], d['template'], d['generator'], d['platform'], 
                        d['rev_count'], d['pages'], d['slides'], d['words'], d['media_count'], d['size']
                    )
                    self.after(0, self._insert_row, row, filepath)

        self.status_var.set(f"Scan Complete. {total} files processed.")
        if timed_out_files:
            report_msg = f"The following {len(timed_out_files)} files timed out (> {TIMEOUT_SECONDS}s) and were skipped:\n\n"
            report_msg += "\n".join(timed_out_files[:15])
            if len(timed_out_files) > 15: report_msg += "\n... and others."
            self.after(0, lambda: messagebox.showwarning("Scan Errors", report_msg))

    def _insert_row(self, values, filepath):
        item_id = self.tree.insert("", "end", values=values)
        self.path_map[item_id] = filepath
        
        verdict = values[1]
        threats = values[2]
        
        if verdict == "SYNTHETIC" or "MACROS" in threats or "INJECTION" in threats:
            self.tree.item(item_id, tags=("danger",))
        elif "HIGH VELOCITY" in threats or "HIDDEN TEXT" in threats or "THUMBNAIL" in threats:
            self.tree.item(item_id, tags=("warning",))
            
        self.tree.tag_configure("danger", background="#4a0e0e") 
        self.tree.tag_configure("warning", background="#4a3b0e")

    # --- EXPORT FEATURE ---
    def export_data(self):
        """Exports the current table to CSV."""
        if not self.tree.get_children():
            messagebox.showwarning("Export", "No data to export.")
            return

        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV (Excel)", "*.csv"), ("All Files", "*.*")])
        if not path: return

        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                
                # Get Visible Column Headers
                cols = self.tree["columns"]
                headers = [self.tree.heading(c)["text"] for c in cols]
                writer.writerow(headers)

                # Write Rows
                for item in self.tree.get_children():
                    writer.writerow(self.tree.item(item)["values"])
            
            messagebox.showinfo("Export", "Data exported successfully!\nYou can open this file in Excel.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")

    # --- DETAIL WINDOW ---
    def on_double_click(self, event):
        item = self.tree.selection()
        if not item: return
        item_id = item[0]
        
        if item_id in self.report_cache:
            self.show_detail_window(self.tree.item(item_id, "values")[0], self.report_cache[item_id], self.path_map.get(item_id))
        else:
            filename = self.tree.item(item_id, "values")[0]
            filepath = self.path_map.get(item_id)
            if filepath:
                self.show_loading_window(filename, filepath, item_id)

    def show_loading_window(self, title, filepath, item_id):
        # Create a modern modal popup
        win = ctk.CTkToplevel(self)
        win.title("Scanning...")
        win.geometry("400x150")
        win.attributes("-topmost", True)
        
        ctk.CTkLabel(win, text="Running Deep Forensic Scan...", font=("Segoe UI", 16, "bold")).pack(pady=(40, 10))
        progress = ctk.CTkProgressBar(win, width=250)
        progress.pack(pady=10)
        progress.configure(mode="indeterminate")
        progress.start()
        
        threading.Thread(target=self._run_deep_scan_thread, args=(win, title, filepath, item_id)).start()

    def _run_deep_scan_thread(self, popup, title, filepath, item_id):
        result_container = {"text": "Error: Scan timed out or crashed."}
        
        def safe_deep_scan():
            capture = io.StringIO()
            original_stdout = sys.stdout
            sys.stdout = capture
            try:
                try:
                    d = BatchAnalyzer().analyze(filepath)
                    print(f"=== {d['filename']} DOSSIER ===")
                    print(f"{'Verdict':<15}: {d['verdict']}")
                    print(f"{'Threats':<15}: {', '.join(d['threats'])}")
                    print("-" * 60)
                    print(f"{'MD5':<15}: {d.get('md5', 'N/A')}")
                    print(f"{'File Modified':<15}: {d['fs_modified']}")
                    print(f"{'Last Saved By':<15}: {d['last_mod_by']}")
                    print("=" * 60 + "\n")
                except: pass

                def safe_run(cls, *args):
                    try: cls(*args).run()
                    except Exception as e: print(f"[ERROR] {cls.__name__}: {e}")

                try:
                    loader = DocLoader(filepath)
                    if loader.load():
                        safe_run(MediaAnalyzer, loader)
                        safe_run(MetadataAnalyzer, loader)
                        safe_run(MacroScanner, loader)
                        safe_run(EmbeddingAnalyzer, loader)
                        safe_run(ExtendedAnalyzer, loader) 
                        safe_run(ExifToolScanner, filepath)
                        if loader.file_type == 'docx':
                            safe_run(OriginAnalyzer, loader)
                            safe_run(AuthorAnalyzer, loader)
                            safe_run(RSIDAnalyzer, loader)
                            safe_run(ThreatScanner, loader)
                        elif loader.file_type == 'pptx':
                            safe_run(PPTXDeepAnalyzer, loader)
                        loader.close()
                except: pass
            except: pass
            finally:
                sys.stdout = original_stdout
                result_container["text"] = capture.getvalue()

        t = threading.Thread(target=safe_deep_scan)
        t.daemon = True
        t.start()
        t.join(timeout=10)
        
        final_text = result_container["text"]
        if t.is_alive():
            final_text += "\n\n[!!!] SCAN TIMED OUT."
            
        self.report_cache[item_id] = final_text
        self.after(0, popup.destroy)
        self.after(0, self.show_detail_window, title, final_text, filepath)

    def show_detail_window(self, title, content, filepath):
        win = ctk.CTkToplevel(self)
        win.title(f"Report: {title}")
        win.geometry("1300x800")
        win.attributes("-topmost", True) # Keep report on top initially
        
        # TABVIEW (Replacing Notebook)
        tabview = ctk.CTkTabview(win)
        tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        tab_report = tabview.add("Forensic Report")
        self._render_report_tab(tab_report, content)

        if ">>>START_SCRIPT_VIEW<<<" in content:
            tab_script = tabview.add("Author Script")
            self._render_script_tab(tab_script, content)
            
        if "THUMBNAIL" in content or "Visual Thumbnail" in content:
            tab_thumb = tabview.add("Visual Thumbnail")
            self._render_thumbnail_tab(tab_thumb, filepath)

    def _render_report_tab(self, parent, content):
        # CTkTextbox with styling
        txt = ctk.CTkTextbox(parent, font=("Consolas", 14), text_color="#dcdcdc", fg_color="#1e1e1e")
        txt.pack(fill="both", expand=True)
        
        # Access underlying widget for tags
        inner_tk_widget = txt._textbox
        inner_tk_widget.tag_config("alert", foreground="#ff5252")
        inner_tk_widget.tag_config("warning", foreground="#ffa726") 
        inner_tk_widget.tag_config("header", foreground="#00A0D6", font=("Consolas", 14, "bold"))
        
        capture_mode = False
        for line in content.splitlines():
            if ">>>START_SCRIPT_VIEW<<<" in line: break
            if "[Content Attribution - Who wrote what?]" in line: continue
            
            tag = None
            if "---" in line and not capture_mode: tag = "header"
            elif "[HIDDEN DATA EXTRACTED]" in line or "[SPEAKER NOTES DATA]" in line:
                capture_mode = True
                inner_tk_widget.insert("end", "\n" + "="*60 + "\n", "warning")
                inner_tk_widget.insert("end", "⚠️  HIDDEN CONTENT DETECTED:\n", "warning")
                continue
            elif capture_mode:
                if "---" in line:
                    capture_mode = False
                    inner_tk_widget.insert("end", "\n")
                    tag = "header"
                elif ">>" in line:
                    clean = line.replace(">>", "").strip()
                    inner_tk_widget.insert("end", f" • {clean}\n", "warning")
                    continue
            elif "[ALERT]" in line or "VERDICT: SYNTHETIC" in line or "[THREAT]" in line: tag = "alert"
            elif "HIDDEN SLIDES" in line or "USER LEAK" in line: tag = "alert"

            inner_tk_widget.insert("end", line + "\n", tag)

        txt.configure(state="disabled")

    def _render_script_tab(self, parent, content):
        txt = ctk.CTkTextbox(parent, font=("Segoe UI", 14), fg_color="#252525")
        txt.pack(fill="both", expand=True)
        inner = txt._textbox
        inner.tag_config("author", foreground="#00A0D6", font=("Segoe UI", 14, "bold"))
        
        parsing = False
        for line in content.splitlines():
            if ">>>START_SCRIPT_VIEW<<<" in line: parsing = True; continue
            if parsing and "|||" in line:
                try:
                    author, text = line.split("|||", 1)
                    inner.insert("end", f"{author}\n", "author")
                    inner.insert("end", f"{text}\n\n")
                except: pass
        txt.configure(state="disabled")

    def _render_thumbnail_tab(self, parent, filepath):
        try:
            loader = DocLoader(filepath)
            if loader.load():
                thumb_file = next((f for f in loader.zip_ref.namelist() if f.lower().startswith("docprops/thumbnail")), None)
                if thumb_file:
                    data = loader.zip_ref.read(thumb_file)
                    img = Image.open(io.BytesIO(data))
                    img.thumbnail((1000, 600))
                    ctk_img = ctk.CTkImage(light_image=img, dark_image=img, size=img.size)
                    ctk.CTkLabel(parent, image=ctk_img, text="").pack(expand=True)
                else:
                    ctk.CTkLabel(parent, text="No Thumbnail Found").pack(expand=True)
                loader.close()
        except: pass

    def sort_col(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try: l.sort(key=lambda x: float(re.sub(r'[^\d.]', '', x[0])), reverse=reverse)
        except: l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l): self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.sort_col(col, not reverse))

    def show_manual(self):
        win = ctk.CTkToplevel(self)
        win.title("OfficeRecon Manual")
        win.geometry("800x600")
        win.attributes("-topmost", True) # Keeps it on top
        t = ctk.CTkTextbox(win, font=("Segoe UI", 14))
        t.pack(fill="both", expand=True)
        t.insert("end", MANUAL_TEXT)
        t.configure(state="disabled")

if __name__ == "__main__":
    app = AdvancedDocRecon()
    app.mainloop()