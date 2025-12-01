import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
import io
import os
import re
import subprocess
import concurrent.futures
import platform
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
        
        style.configure("Vertical.TScrollbar", gripcount=0, background=self.scroll_fg, darkcolor=self.scroll_fg, lightcolor=self.scroll_fg, troughcolor=self.scroll_bg, bordercolor=self.scroll_bg, arrowcolor="white", arrowsize=25)
        style.configure("Horizontal.TScrollbar", gripcount=0, background=self.scroll_fg, darkcolor=self.scroll_fg, lightcolor=self.scroll_fg, troughcolor=self.scroll_bg, bordercolor=self.scroll_bg, arrowcolor="white", arrowsize=25)
        
        style.configure("TNotebook", background=self.bg_dark)
        style.configure("TNotebook.Tab", background="#444", foreground="white", padding=[15, 5], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", self.accent)], foreground=[("selected", "white")])

        self.root.configure(bg=self.bg_dark)
        self.path_map = {}     
        self.report_cache = {} 
        self.image_ref = None 

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
        
        # Use a Text widget to allow multi-color text with ZERO spacing
        # We create a small text box that looks exactly like a label
        logo_text = tk.Text(toolbar, height=1, width=15, font=("Consolas", 18, "bold"),
                            bg="#1a1a1a", fg="white", borderwidth=0, highlightthickness=0)
        logo_text.pack(side=tk.LEFT, padx=15, pady=10)
        
        # Insert the full text "DocRecon"
        logo_text.insert(tk.END, "DocRecon")
        
        # Apply the accent color (Blue) to "Doc" (First 3 characters: index 1.0 to 1.3)
        logo_text.tag_add("blue", "1.0", "1.3")
        logo_text.tag_config("blue", foreground=self.accent)
        
        # Disable editing so it acts like a static label
        logo_text.configure(state="disabled", cursor="arrow")

        btn_dir = tk.Button(toolbar, text="Load Folder", bg="#444", fg="white", command=self.load_batch_folder, relief="flat")
        btn_dir.pack(side=tk.RIGHT, padx=10, pady=10)

    def create_table(self):
        cols = (
            "filename", "verdict", "threats", "md5", "hidden_text", # <--- [MODIFIED] Added md5
            "author", "last_mod", "printed", 
            "meta_created", "meta_modified", 
            "title", "leaked_user", 
            "fs_modified", "fs_accessed", "fs_created", 
            "zip_modified", 
            "edit_time", "status", "category", 
            "rsid_count", "template", "app", "platform", "rev", "pages", "slides", "words", "media", "size"
        )
        frame = tk.Frame(self.root, bg=self.bg_dark)
        frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        
        headers = {
            "filename": "File Name", "verdict": "Verdict", "threats": "Threats/Flags",
            "md5": "MD5 Hash", # <--- [MODIFIED] Added Header
            "hidden_text": "Hidden Content", 
            "author": "Creator", "last_mod": "Last Saved By", "printed": "Last Printed (Date)",
            "meta_created": "Metadata Created", "meta_modified": "Metadata Modified",
            "title": "Original Title", "leaked_user": "Embedded User",
            "fs_modified": "File Sys Modified", "fs_accessed": "File Sys Access", "fs_created": "File Sys Created",
            "zip_modified": "Zip Internal Date",
            "edit_time": "Edit Time", "status": "Status", "category": "Category",
            "rsid_count": "RSIDs", "template": "Template", "app": "Software", "platform": "OS", 
            "rev": "Rev", "pages": "Pg", "slides": "Slides", "words": "Words", "media": "Imgs", "size": "Size"
        }
        
        for col in cols:
            self.tree.heading(col, text=headers[col], command=lambda c=col: self.sort_col(c, False))
            w = 100
            if col == "filename": w = 300
            if col == "threats": w = 200
            if col == "md5": w = 220 # <--- [MODIFIED] Set width for MD5
            if col == "title": w = 200
            if col in ["author", "last_mod"]: w = 150
            if "fs_" in col or "meta_" in col or "zip_" in col or col == "printed": w = 220 
            if col in ["rev", "pages", "media", "rsid_count", "slides"]: w = 60
            self.tree.column(col, width=w, anchor="w" if col in ["filename", "threats", "title", "hidden_text", "md5"] else "center") # <--- [MODIFIED] Added md5 to left anchor list

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
        win = tk.Toplevel(self.root)
        win.title(f"Scanning: {title}")
        win.geometry("400x150")
        win.configure(bg=self.bg_dark)
        lbl = tk.Label(win, text="Running Deep Forensic Scan...\nPlease Wait.", font=("Segoe UI", 12), bg=self.bg_dark, fg="white")
        lbl.pack(expand=True)
        threading.Thread(target=self._run_deep_scan_thread, args=(win, title, filepath, item_id)).start()
        
    def _execution_loop(self, files):
        total = len(files)
        timed_out_files = []
        TIMEOUT_SECONDS = 5  # Strict 5-second limit per file

        for i, filepath in enumerate(files):
            filename = os.path.basename(filepath)
            self.status_var.set(f"Analyzing {i+1}/{total}: {filename}...")

            result_container = {"data": None}

            def target_scan():
                try:
                    scanner = BatchAnalyzer()
                    result_container["data"] = scanner.analyze(filepath)
                except Exception: pass

            # Spawn a disposable daemon thread
            t = threading.Thread(target=target_scan)
            t.daemon = True
            t.start()

            # Wait strictly for X seconds
            t.join(timeout=TIMEOUT_SECONDS)

            if t.is_alive():
                print(f"[TIMEOUT] Abandoning stuck file: {filename}")
                # Store FULL PATH as requested
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
                    self.root.after(0, self._insert_row, row, filepath)

        self.status_var.set(f"Scan Complete. {total} files processed.")

        # REPORTING: Show popup with FULL PATHS
        if timed_out_files:
            report_msg = f"The following {len(timed_out_files)} files timed out (> {TIMEOUT_SECONDS}s) and were skipped:\n\n"
            # Show first 15 full paths to avoid massive popup
            report_msg += "\n".join(timed_out_files[:15])
            if len(timed_out_files) > 15: report_msg += "\n... and others."
            
            self.root.after(0, lambda: messagebox.showwarning("Scan Completed with Errors", report_msg))

    def _run_deep_scan_thread(self, popup, title, filepath, item_id):
        # We use a container to get the text back from the thread
        result_container = {"text": "Error: Scan timed out or crashed."}
        
        def safe_deep_scan():
            capture = io.StringIO()
            original_stdout = sys.stdout
            sys.stdout = capture
            
            try:
                # 1. DOSSIER
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
                except Exception as e: print(f"[ERROR] Dossier gen failed: {e}")

                # 2. RUN ANALYZERS
                def safe_run(cls, *args):
                    try: cls(*args).run()
                    except Exception as e: print(f"[ERROR] {cls.__name__}: {e}")

                try:
                    loader = DocLoader(filepath)
                    if loader.load():
                        # Universal
                        safe_run(MediaAnalyzer, loader)
                        safe_run(MetadataAnalyzer, loader)
                        safe_run(MacroScanner, loader)
                        safe_run(EmbeddingAnalyzer, loader)
                        safe_run(ExtendedAnalyzer, loader) 
                        safe_run(ExifToolScanner, filepath)
                        
                        # Type Specific
                        if loader.file_type == 'docx':
                            safe_run(OriginAnalyzer, loader)
                            safe_run(AuthorAnalyzer, loader)
                            safe_run(RSIDAnalyzer, loader)
                            safe_run(ThreatScanner, loader)
                        elif loader.file_type == 'pptx':
                            safe_run(PPTXDeepAnalyzer, loader)
                        
                        loader.close()
                except Exception as e: print(f"[CRITICAL ERROR] Loader failed: {e}")
            
            except Exception as e:
                print(f"Deep Scan Crash: {e}")
            finally:
                sys.stdout = original_stdout
                result_container["text"] = capture.getvalue()

        # RUN IN DAEMON THREAD WITH TIMEOUT (Protects against crashes)
        t = threading.Thread(target=safe_deep_scan)
        t.daemon = True
        t.start()
        
        # Give the deep scan 10 seconds max to finish
        t.join(timeout=10)
        
        if t.is_alive():
            # If still running after 10s, we assume it hung/crashed
            error_msg = result_container["text"] + "\n\n[!!!] SCAN TIMED OUT: The file is too complex or corrupted."
            self.report_cache[item_id] = error_msg
            self.root.after(0, popup.destroy)
            self.root.after(0, self.show_detail_window, title, error_msg, filepath)
        else:
            # Finished successfully
            final_text = result_container["text"]
            self.report_cache[item_id] = final_text
            self.root.after(0, popup.destroy)
            self.root.after(0, self.show_detail_window, title, final_text, filepath)
            
    def show_detail_window(self, title, content, filepath):
        win = tk.Toplevel(self.root)
        win.title(f"Deep Scan Report: {title}")
        win.geometry("1300x800")
        win.configure(bg="#212121")

        notebook = ttk.Notebook(win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        tab_report = ttk.Frame(notebook)
        notebook.add(tab_report, text="Forensic Report")
        self._render_report_tab(tab_report, content)

        if ">>>START_SCRIPT_VIEW<<<" in content:
            tab_script = ttk.Frame(notebook)
            notebook.add(tab_script, text="Author Script")
            self._render_script_tab(tab_script, content)
            
        if "THUMBNAIL" in content or "Visual Thumbnail" in content:
            tab_thumb = ttk.Frame(notebook)
            notebook.add(tab_thumb, text="Visual Thumbnail")
            self._render_thumbnail_tab(tab_thumb, filepath)

    def _render_thumbnail_tab(self, parent, filepath):
        try:
            loader = DocLoader(filepath)
            if loader.load():
                thumb_file = None
                for f in loader.zip_ref.namelist():
                    if f.lower().startswith("docprops/thumbnail"):
                        thumb_file = f
                        break
                
                if thumb_file and thumb_file.lower().endswith(('.jpg', '.jpeg', '.png')):
                    thumb_data = loader.zip_ref.read(thumb_file)
                    img = Image.open(io.BytesIO(thumb_data))
                    img.thumbnail((1200, 700))
                    self.image_ref = ImageTk.PhotoImage(img)
                    lbl = tk.Label(parent, image=self.image_ref, bg="#212121")
                    lbl.pack(expand=True)
                else:
                    tk.Label(parent, text="No visual thumbnail found.", fg="white", bg="#212121").pack(expand=True)
                loader.close()
        except: pass

    def _render_report_tab(self, parent, content):
        findings = []
        capture_mode = False
        lines_to_display = []
        for line in content.splitlines():
            if ">>>START_SCRIPT_VIEW<<<" in line: break
            if "[Content Attribution - Who wrote what?]" in line: continue
            lines_to_display.append(line)
            
            if "[HIDDEN DATA EXTRACTED]" in line or "[SPEAKER NOTES DATA]" in line:
                capture_mode = True
                findings.append("⚠️ HIDDEN TEXT / NOTES DISCOVERED:")
            elif "[THREAT]" in line or "Corporate Server URL" in line or "[USER LEAK]" in line or "HIDDEN SLIDES" in line:
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
            elif "[ALERT]" in line or "VERDICT: SYNTHETIC" in line or "HIDDEN" in line or "LEAK" in line: tag = "alert"
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