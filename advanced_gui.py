import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
import io
import os
import re
import subprocess
import platform

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

class AdvancedDocRecon:
    def __init__(self, root):
        self.root = root
        self.root.title("DocRecon | Forensic Table View")
        
        try: self.root.state('zoomed')
        except: self.root.geometry("1600x900")

        style = ttk.Style()
        style.theme_use('clam') 
        self.bg_dark = "#212121"
        self.accent = "#00A0D6" 
        self.scroll_bg = "#444"
        self.scroll_fg = "#00A0D6"
        
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", font=("Segoe UI", 10), rowheight=35)
        style.configure("Treeview.Heading", background="#444", foreground="white", font=("Segoe UI", 11, "bold"))
        style.map("Treeview", background=[('selected', self.accent)])
        
        style.configure("Vertical.TScrollbar", gripcount=0,
                        background=self.scroll_fg, darkcolor=self.scroll_fg, lightcolor=self.scroll_fg,
                        troughcolor=self.scroll_bg, bordercolor=self.scroll_bg, arrowcolor="white", arrowsize=25)
        style.configure("Horizontal.TScrollbar", gripcount=0,
                        background=self.scroll_fg, darkcolor=self.scroll_fg, lightcolor=self.scroll_fg,
                        troughcolor=self.scroll_bg, bordercolor=self.scroll_bg, arrowcolor="white", arrowsize=25)
        
        style.configure("TNotebook", background=self.bg_dark)
        style.configure("TNotebook.Tab", background="#444", foreground="white", padding=[15, 5], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", self.accent)], foreground=[("selected", "white")])

        self.root.configure(bg=self.bg_dark)
        self.path_map = {}     
        self.report_cache = {} 

        self.create_menubar()
        self.create_toolbar()
        self.create_table()
        self.create_context_menu()
        self.create_statusbar()

    def create_menubar(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Load Single File...", command=self.load_target_file)
        file_menu.add_command(label="Load Directory (Batch)...", command=self.load_batch_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Forensic Manual", command=self.show_manual)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def create_toolbar(self):
        toolbar = tk.Frame(self.root, bg="#1a1a1a", height=50)
        toolbar.pack(fill=tk.X, side=tk.TOP)
        toolbar.pack_propagate(False)
        tk.Label(toolbar, text="DOCRECON TABLE", font=("Consolas", 18, "bold"), bg="#1a1a1a", fg=self.accent).pack(side=tk.LEFT, padx=15)
        btn_dir = tk.Button(toolbar, text="Load Folder", bg="#444", fg="white", command=self.load_batch_folder, relief="flat")
        btn_dir.pack(side=tk.RIGHT, padx=10, pady=10)

    def create_table(self):
        # --- ADDED 'hidden_text' column ---
        cols = (
            "filename", "verdict", "threats", "hidden_text", # <--- NEW
            "title", "leaked_user", 
            "fs_modified", "fs_accessed", "fs_created", 
            "zip_modified", "meta_created", "meta_modified",
            "author", "last_mod", "printed", 
            "edit_time", "status", "category", 
            "rsid_count", "template", "app", "platform", "rev", "pages", "words", "media", "size"
        )
        frame = tk.Frame(self.root, bg=self.bg_dark)
        frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        
        headers = {
            "filename": "File Name", "verdict": "Verdict", "threats": "Threats/Flags",
            "hidden_text": "Hidden Content", # <--- Header
            "title": "Original Title", "leaked_user": "Embedded User",
            "fs_modified": "File Modification Date/Time",
            "fs_accessed": "File Access Date/Time",
            "fs_created": "File Creation Date/Time",
            "zip_modified": "Zip Modify Date",
            "meta_created": "Metadata create",
            "meta_modified": "Metadata modify",
            "author": "Creator (Meta)", "last_mod": "Last Saved By (Meta)", "printed": "Last Printed",
            "edit_time": "Edit Time", "status": "Status", "category": "Category",
            "rsid_count": "RSIDs", "template": "Template", "app": "Software", "platform": "OS", 
            "rev": "Rev", "pages": "Pg", "words": "Words", "media": "Imgs", "size": "Size"
        }
        
        for col in cols:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self.sort_col(c, False))
            w = 100
            if col == "filename": w = 250
            if col == "threats": w = 180
            if col == "title": w = 200
            if col == "hidden_text": w = 200 # Wide enough to read
            if "fs_" in col or "meta_" in col or "zip_" in col: w = 220 
            if col in ["rev", "pages", "media", "rsid_count"]: w = 60
            self.tree.column(col, width=w, anchor="w" if col in ["filename", "threats", "title", "hidden_text"] else "center")

        vsb = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview, style="Vertical.TScrollbar")
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=self.tree.xview, style="Horizontal.TScrollbar")
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        
        self.tree.bind("<Double-1>", self.on_double_click)
        self.tree.bind("<Button-3>", self.show_context_menu)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self.root, tearoff=0)
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

    def create_statusbar(self):
        self.status_var = tk.StringVar(value="Ready.")
        tk.Label(self.root, textvariable=self.status_var, bg="#1a1a1a", fg="#888", anchor="w", padx=10).pack(side=tk.BOTTOM, fill=tk.X)

    def load_target_file(self):
        path = filedialog.askopenfilename(filetypes=[("Documents", "*.docx *.odt")])
        if path: self.run_scan([path], clear=True)

    def load_batch_folder(self):
        path = filedialog.askdirectory()
        if path:
            files = []
            for root, _, filenames in os.walk(path):
                for f in filenames:
                    if f.lower().endswith(('.docx', '.odt')) and not f.startswith('~$'):
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
        scanner = BatchAnalyzer()
        
        for i, filepath in enumerate(files):
            filename = os.path.basename(filepath)
            self.status_var.set(f"Analyzing {i+1}/{total}: {filename}...")
            
            d = scanner.analyze(filepath)
            threat_str = ", ".join(d.get('threats', []))
            
            row = (
                d['filename'], d['verdict'], threat_str, d['hidden_text'], # Added
                d['title'], d['leaked_user'],
                d['fs_modified'], d['fs_accessed'], d['fs_created'], 
                d['zip_modified'], d['meta_created'], d['meta_modified'],
                d['author'], d['last_mod_by'], d['printed'],
                d['edit_time'], d['status'], d['category'],
                d['rsid_count'], d['template'], d['generator'], d['platform'], 
                d['rev_count'], d['pages'], d['words'], d['media_count'], d['size']
            )
            
            self.root.after(0, self._insert_row, row, filepath)

        self.status_var.set(f"Scan Complete. {total} files processed.")

    def _insert_row(self, values, filepath):
        item_id = self.tree.insert("", "end", values=values)
        self.path_map[item_id] = filepath
        
        verdict = values[1]
        threats = values[2]
        
        if verdict == "SYNTHETIC" or "MACROS" in threats or "INJECTION" in threats:
            self.tree.item(item_id, tags=("danger",))
        elif "HIGH VELOCITY" in threats or "HIDDEN TEXT" in threats or "USER LEAK" in threats:
            self.tree.item(item_id, tags=("warning",))
            
        self.tree.tag_configure("danger", background="#4a0e0e") 
        self.tree.tag_configure("warning", background="#4a3b0e")

    def on_double_click(self, event):
        item = self.tree.selection()
        if not item: return
        item_id = item[0]
        
        if item_id in self.report_cache:
            self.show_detail_window(self.tree.item(item_id, "values")[0], self.report_cache[item_id])
        else:
            filename = self.tree.item(item_id, "values")[0]
            filepath = self.path_map.get(item_id)
            if filepath:
                self.show_loading_window(filename, filepath, item_id)

    def show_loading_window(self, title, filepath, item_id):
        win = tk.Toplevel(self.root)
        win.title(f"Scanning: {title}")
        win.geometry("400x150")
        win.configure(bg=self.bg_dark)
        
        lbl = tk.Label(win, text="Running Deep Forensic Scan...\nPlease Wait.", font=("Segoe UI", 12), bg=self.bg_dark, fg="white")
        lbl.pack(expand=True)
        
        threading.Thread(target=self._run_deep_scan_thread, args=(win, title, filepath, item_id)).start()

    def _run_deep_scan_thread(self, popup, title, filepath, item_id):
        capture = io.StringIO()
        original_stdout = sys.stdout
        sys.stdout = capture
        
        try:
            loader = DocLoader(filepath)
            if loader.load():
                if loader.file_type == 'docx':
                    OriginAnalyzer(loader).run()
                    AuthorAnalyzer(loader).run()
                    RSIDAnalyzer(loader).run()
                    ThreatScanner(loader).run()
                    MacroScanner(loader).run()
                    MediaAnalyzer(loader).run()
                    ExtendedAnalyzer(loader).run()
                    EmbeddingAnalyzer(loader).run()
                elif loader.file_type == 'odt':
                    MediaAnalyzer(loader).run()
                    MetadataAnalyzer(loader).run()
                loader.close()
        except Exception as e: print(f"[ERROR] {e}")
        
        sys.stdout = original_stdout
        report_text = capture.getvalue()
        
        self.report_cache[item_id] = report_text
        self.root.after(0, popup.destroy)
        self.root.after(0, self.show_detail_window, title, report_text)

    def show_detail_window(self, title, content):
        win = tk.Toplevel(self.root)
        win.title(f"Deep Scan Report: {title}")
        win.geometry("1300x800")
        win.configure(bg="#212121")

        notebook = ttk.Notebook(win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tab_report = ttk.Frame(notebook)
        notebook.add(tab_report, text="Forensic Report")
        self._render_report_tab(tab_report, content)

        tab_script = ttk.Frame(notebook)
        notebook.add(tab_script, text="Author Script")
        self._render_script_tab(tab_script, content)

    def _render_report_tab(self, parent, content):
        findings = []
        capture_mode = False
        lines_to_display = []
        for line in content.splitlines():
            if ">>>START_SCRIPT_VIEW<<<" in line: break
            if "[Content Attribution - Who wrote what?]" in line: continue
            lines_to_display.append(line)
            
            if "[HIDDEN DATA EXTRACTED]" in line:
                capture_mode = True
                findings.append("⚠️ HIDDEN TEXT DISCOVERED:")
            elif "[THREAT]" in line or "Corporate Server URL" in line or "[USER LEAK]" in line:
                findings.append(f"⚠️ {line.strip()}")
            elif capture_mode and ">>" in line:
                findings.append(line.strip())
            elif capture_mode and "---" in line:
                capture_mode = False

        if findings:
            alert_frame = tk.Frame(parent, bg="#4a0e0e", padx=10, pady=10)
            alert_frame.pack(fill=tk.X)
            for f in findings:
                tk.Label(alert_frame, text=f, bg="#4a0e0e", fg="white", font=("Consolas", 10), wraplength=1200, justify="left").pack(anchor="w")

        txt = scrolledtext.ScrolledText(parent, font=("Consolas", 10), bg="#1e1e1e", fg="#dcdcdc")
        txt.pack(fill=tk.BOTH, expand=True)
        txt.tag_config("alert", foreground="#ff5252")
        txt.tag_config("header", foreground=self.accent, font=("Consolas", 11, "bold"))
        
        for line in lines_to_display:
            tag = None
            if "---" in line: tag = "header"
            elif "[ALERT]" in line or "VERDICT: SYNTHETIC" in line or "HIDDEN DATA" in line or "LEAK" in line: tag = "alert"
            txt.insert(tk.END, line + "\n", tag)
        txt.configure(state='disabled')

    def _render_script_tab(self, parent, content):
        txt = scrolledtext.ScrolledText(parent, font=("Segoe UI", 11), bg="#252525", fg="white", padx=20, pady=20)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.tag_config("author", foreground=self.accent, font=("Segoe UI", 11, "bold"))
        txt.tag_config("text", foreground="#dcdcdc")
        txt.tag_config("unknown", foreground="#888", font=("Segoe UI", 11, "italic"))

        parsing = False
        for line in content.splitlines():
            if ">>>START_SCRIPT_VIEW<<<" in line:
                parsing = True
                continue
            if parsing and "|||" in line:
                try:
                    author, text = line.split("|||", 1)
                    tag = "author" if "Unknown" not in author else "unknown"
                    txt.insert(tk.END, f"{author}\n", tag)
                    txt.insert(tk.END, f"{text}\n\n", "text")
                except: pass
        
        if not parsing:
            txt.insert(tk.END, "No attribution data found. This document might be ODT or lack RSID history.")
        txt.configure(state='disabled')

    def sort_col(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        try: l.sort(key=lambda x: float(re.sub(r'[^\d.]', '', x[0])), reverse=reverse)
        except: l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l): self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.sort_col(col, not reverse))

    def show_manual(self):
        win = tk.Toplevel(self.root)
        win.title("DocRecon Manual")
        win.geometry("800x600")
        t = tk.Text(win, bg="#222", fg="#eee", font=("Segoe UI", 11), padx=20, pady=20)
        t.pack(fill="both", expand=1)
        t.insert("end", MANUAL_TEXT); t.config(state="disabled")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedDocRecon(root)
    root.mainloop()