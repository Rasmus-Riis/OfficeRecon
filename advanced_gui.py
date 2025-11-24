import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import sys
import io
import os
import re

# Import your existing engines
from core.loader import DocLoader
from analyzers.origin import OriginAnalyzer
from analyzers.metadata import MetadataAnalyzer
from analyzers.rsid import RSIDAnalyzer
from analyzers.threats import ThreatScanner
from analyzers.styles import StyleAnalyzer
from analyzers.deep_scan import DeepScanAnalyzer
from analyzers.platform import PlatformAnalyzer
from analyzers.fields import FieldAnalyzer
from analyzers.embeddings import EmbeddingAnalyzer
from analyzers.authors import AuthorAnalyzer
from analyzers.genealogy import GenealogyMapper

class AdvancedDocRecon:
    def __init__(self, root):
        self.root = root
        self.root.title("DocRecon | Forensic Dashboard")
        self.root.geometry("1100x750")
        
        # --- Theme & Style ---
        style = ttk.Style()
        style.theme_use('clam') 
        
        # Define colors
        self.bg_dark = "#212121"
        self.fg_text = "#ECECEC"
        self.accent = "#00A0D6" # "Police" blue
        
        # Configure styles
        style.configure("TFrame", background=self.bg_dark)
        style.configure("TLabel", background=self.bg_dark, foreground=self.fg_text, font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), background="#444", foreground="white")
        style.map("TButton", background=[('active', self.accent)])
        style.configure("TNotebook", background=self.bg_dark, tabmargins=[2, 5, 2, 0])
        style.configure("TNotebook.Tab", background="#444", foreground="white", padding=[10, 5], font=("Segoe UI", 10))
        style.map("TNotebook.Tab", background=[("selected", self.accent)], foreground=[("selected", "white")])

        self.root.configure(bg=self.bg_dark)

        # --- 1. Initialize Internal State ---
        self.analyzers_map = {} 
        self.alert_count = 0

        # --- 2. Build Layout ---
        self.create_header()
        self.create_main_area()
        self.create_statusbar()

        # --- 3. Auto-Load from Command Line ---
        if len(sys.argv) > 1:
            potential_file = sys.argv[1]
            if os.path.exists(potential_file):
                self.target_path = potential_file
                self.lbl_target.config(text=os.path.basename(potential_file), fg="white")
                self.status_var.set("Target Loaded via CLI. Ready to scan.")

    def create_header(self):
        header_frame = tk.Frame(self.root, bg="#1a1a1a", height=60)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        header_frame.pack_propagate(False)

        lbl_title = tk.Label(header_frame, text="DOCRECON // FORENSIC SUITE", font=("Consolas", 20, "bold"), bg="#1a1a1a", fg=self.accent)
        lbl_title.pack(side=tk.LEFT, padx=20, pady=10)

        # Controls Area in Header
        btn_load = tk.Button(header_frame, text="LOAD FILE / DIR", bg="#444", fg="white", font=("Segoe UI", 9), command=self.load_target, relief="flat", padx=15)
        btn_load.pack(side=tk.RIGHT, padx=10, pady=12)
        
        self.lbl_target = tk.Label(header_frame, text="No Target Selected", font=("Segoe UI", 10, "italic"), bg="#1a1a1a", fg="#888")
        self.lbl_target.pack(side=tk.RIGHT, padx=10)

    def create_main_area(self):
        main_frame = tk.Frame(self.root, bg=self.bg_dark)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # 1. Dashboard (Summary)
        self.tab_dash = self.create_tab("Dashboard")
        self.create_dashboard_ui(self.tab_dash)

        # 2. Origin & OS
        self.tab_origin = self.create_console_tab("Origin & Platform")
        
        # 3. Authors & RSID
        self.tab_users = self.create_console_tab("Authors & History")
        
        # 4. Metadata & Styles
        self.tab_meta = self.create_console_tab("Metadata & Styles")
        
        # 5. Deep Scan (Hidden data)
        self.tab_deep = self.create_console_tab("Deep Artifacts")

    def create_tab(self, title):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=title)
        return frame

    def create_console_tab(self, title):
        """Creates a tab with a read-only, color-coded text console."""
        frame = self.create_tab(title)
        
        # Text Widget
        txt = scrolledtext.ScrolledText(frame, state='disabled', font=("Consolas", 10), bg="#1e1e1e", fg="#dcdcdc", insertbackground="white")
        txt.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure Tags for Highlighting
        txt.tag_config("danger", foreground="#ff5252", font=("Consolas", 10, "bold")) # Red
        txt.tag_config("warning", foreground="#ffb74d") # Orange
        txt.tag_config("success", foreground="#69f0ae") # Green
        txt.tag_config("info", foreground="#40c4ff")    # Blue
        txt.tag_config("header", foreground="white", font=("Consolas", 11, "bold", "underline"))

        self.analyzers_map[title] = txt
        return txt

    def create_dashboard_ui(self, parent):
        left_col = tk.Frame(parent, bg=self.bg_dark)
        left_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        right_col = tk.Frame(parent, bg=self.bg_dark)
        right_col.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- Left: Actions & Status ---
        action_frame = tk.LabelFrame(left_col, text=" Control ", bg=self.bg_dark, fg="white", font=("Segoe UI", 10, "bold"))
        action_frame.pack(fill=tk.X, pady=5)
        
        self.btn_run = tk.Button(action_frame, text="START FORENSIC ANALYSIS", bg=self.accent, fg="white", font=("Segoe UI", 12, "bold"), relief="flat", command=self.run_analysis)
        self.btn_run.pack(fill=tk.X, padx=10, pady=15)

        # Alert Counter
        self.alert_frame = tk.Frame(left_col, bg="#330000", height=100, relief="sunken", borderwidth=2)
        self.alert_frame.pack(fill=tk.X, pady=10)
        self.alert_frame.pack_propagate(False)
        
        self.lbl_alert_count = tk.Label(self.alert_frame, text="0", font=("Segoe UI", 36, "bold"), bg="#330000", fg="#ff5252")
        self.lbl_alert_count.pack(side=tk.LEFT, padx=20)
        tk.Label(self.alert_frame, text="THREATS / ANOMALIES", font=("Segoe UI", 12), bg="#330000", fg="#ff8a80").pack(side=tk.LEFT)

        # --- Right: Findings Log ---
        lbl_findings = tk.Label(right_col, text="Artifact & Anomaly Overview", bg=self.bg_dark, fg="white", font=("Segoe UI", 10, "bold"))
        lbl_findings.pack(anchor="w")
        
        self.txt_findings = scrolledtext.ScrolledText(right_col, state='disabled', height=20, bg="#252525", fg="white", font=("Segoe UI", 10))
        self.txt_findings.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard Tags
        self.txt_findings.tag_config("crit", foreground="#ff5252", font=("Segoe UI", 10, "bold"))  # Red
        self.txt_findings.tag_config("warn", foreground="#ffb74d", font=("Segoe UI", 10))         # Orange
        self.txt_findings.tag_config("pass", foreground="#69f0ae", font=("Segoe UI", 10, "bold")) # Green
        self.txt_findings.tag_config("info", foreground="#81d4fa", font=("Segoe UI", 10))         # Light Blue
        self.txt_findings.tag_config("header", foreground="white", font=("Segoe UI", 10, "bold"))

    def create_statusbar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("Ready.")
        status_bar = tk.Label(self.root, textvariable=self.status_var, bg="#1a1a1a", fg="#888", font=("Segoe UI", 9), anchor="w", padx=10)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    # --- Logic ---

    def load_target(self):
        choice = messagebox.askyesno("Select Target Type", 
                                     "Do you want to scan a Single File?\n\nYES: Load .docx File\nNO: Load Directory (Batch Scan)")
        
        path = None
        if choice:
            path = filedialog.askopenfilename(filetypes=[("Word Documents", "*.docx")])
        else:
            path = filedialog.askdirectory()

        if path:
            self.target_path = path
            self.lbl_target.config(text=os.path.basename(path), fg="white")
            self.status_var.set("Target Loaded. Ready to scan.")

    def log_to_tab(self, tab_name, text):
        """Standard Logger for Tab Consoles"""
        widget = self.analyzers_map.get(tab_name)
        if not widget: return

        widget.config(state='normal')
        
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        clean_text = ansi_escape.sub('', text)
        
        # Color coding for the specific module tab
        tag = None
        if "[ALERT]" in text or "SYNTHETIC" in text or "Leaked" in text:
            tag = "danger"
        elif "[WARN]" in text or "Suspicious" in text or "HYPERLINK" in text:
            tag = "warning"
        elif "[PASS]" in text or "ORGANIC" in text:
            tag = "success"
        elif "[INFO]" in text:
            tag = "info"
        elif "---" in text and "Analysis" in text:
            tag = "header"

        widget.insert(tk.END, clean_text + "\n", tag)
        widget.see(tk.END)
        widget.config(state='disabled')

        # --- DASHBOARD FEED LOGIC (Promote to Overview) ---
        # We strip the ugly [INFO] tags for the main dashboard to look like a summary
        
        # 1. Critical Threats -> RED / ORANGE
        if "[ALERT]" in text or "SYNTHETIC" in text or "Leaked" in text:
             self.add_dashboard_entry(f"(!) {clean_text}", "crit")
             self.increment_alert()
        elif "[WARN]" in text:
             self.add_dashboard_entry(f"(!) {clean_text}", "warn")
             self.increment_alert()

        # 2. Key Verdicts -> GREEN
        elif "VERDICT:" in text:
             self.add_dashboard_entry(f"(=) {clean_text}", "pass")

        # 3. Artifact Summaries -> BLUE
        # Catch "Found", "Deanonymized", "Detected", "Persistent"
        elif "Found" in text and "[INFO]" in text:
             msg = clean_text.replace('[INFO]', '').strip()
             self.add_dashboard_entry(f" •  {msg}", "info")
        
        elif "Deanonymized" in text:
             msg = clean_text.replace('[PASS]', '').strip()
             self.add_dashboard_entry(f" •  {msg}", "pass")
             
        elif "Mac OS detected" in text or "Windows environment" in text:
             msg = clean_text.replace('[INFO]', '').replace('[WARN]', '').strip()
             self.add_dashboard_entry(f" •  OS: {msg}", "info")

        elif "Persistent Document ID" in text:
             msg = clean_text.replace('[INFO]', '').strip()
             self.add_dashboard_entry(f" •  {msg}", "info")

    def add_dashboard_entry(self, text, tag):
        self.txt_findings.config(state='normal')
        self.txt_findings.insert(tk.END, f"{text}\n", tag)
        self.txt_findings.see(tk.END)
        self.txt_findings.config(state='disabled')

    def increment_alert(self):
        self.alert_count += 1
        self.lbl_alert_count.config(text=str(self.alert_count))

    def run_analysis(self):
        if not hasattr(self, 'target_path'):
            messagebox.showerror("Error", "Please load a file or directory first.")
            return

        # Reset UI
        self.alert_count = 0
        self.lbl_alert_count.config(text="0")
        self.txt_findings.config(state='normal')
        self.txt_findings.delete(1.0, tk.END)
        self.txt_findings.config(state='disabled')
        
        for w in self.analyzers_map.values():
            w.config(state='normal')
            w.delete(1.0, tk.END)
            w.config(state='disabled')

        # Start Thread
        t = threading.Thread(target=self._execute_pipeline)
        t.start()

    def _execute_pipeline(self):
        self.btn_run.config(state='disabled', text="SCANNING...")
        
        # Helper to redirect output
        def run_module(module_class, tab_name, arg):
            self.status_var.set(f"Running {tab_name}...")
            capture = io.StringIO()
            sys.stdout = capture
            try:
                engine = module_class(arg)
                engine.run()
            except Exception as e:
                print(f"[ERROR] Module Failed: {e}")
            sys.stdout = sys.__stdout__
            output = capture.getvalue()
            for line in output.splitlines():
                self.root.after(0, self.log_to_tab, tab_name, line)

        try:
            # === MODE 1: DIRECTORY / GENEALOGY ===
            if os.path.isdir(self.target_path):
                self.status_var.set("Directory Detected. Running Genealogy Mapper...")
                run_module(GenealogyMapper, "Authors & History", self.target_path)
                self.log_to_tab("Dashboard", "[INFO] Directory Scan Completed. Check 'Authors & History' tab.")

            # === MODE 2: SINGLE FILE DEEP SCAN ===
            else:
                self.status_var.set("Initializing Forensic Loader...")
                loader = DocLoader(self.target_path)
                if loader.load():
                    
                    # 1. Origin Tab
                    run_module(OriginAnalyzer, "Origin & Platform", loader)
                    run_module(PlatformAnalyzer, "Origin & Platform", loader)
                    
                    # 2. Authors Tab
                    run_module(AuthorAnalyzer, "Authors & History", loader)
                    run_module(RSIDAnalyzer, "Authors & History", loader)
                    
                    # 3. Metadata Tab
                    run_module(MetadataAnalyzer, "Metadata & Styles", loader)
                    run_module(StyleAnalyzer, "Metadata & Styles", loader)
                    
                    # 4. Deep Scan Tab
                    run_module(ThreatScanner, "Deep Artifacts", loader)
                    run_module(DeepScanAnalyzer, "Deep Artifacts", loader)
                    run_module(FieldAnalyzer, "Deep Artifacts", loader)
                    run_module(EmbeddingAnalyzer, "Deep Artifacts", loader)

                    loader.close()
                    self.status_var.set("Analysis Complete.")
                
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            print(e)
        finally:
            self.btn_run.config(state='normal', text="START FORENSIC ANALYSIS")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedDocRecon(root)
    root.mainloop()