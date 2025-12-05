import customtkinter as ctk
import io
from PIL import Image
from core.loader import DocLoader

class ReportWindow(ctk.CTkToplevel):
    def __init__(self, master, title, main_text, author_text, filepath):
        super().__init__(master)
        self.title(f"Report: {title}")
        self.geometry("1200x800")
        self.attributes("-topmost", True)
        
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        self._create_report_tab(main_text)
        
        if author_text.strip():
            self._create_author_tab(author_text)
        
        # Only create thumbnail tab if thumbnail exists
        if self._has_thumbnail(filepath):
            self._create_thumbnail_tab(filepath)

    def _create_report_tab(self, text):
        tab = self.tabview.add("Forensic Report")
        tb = ctk.CTkTextbox(tab, font=("Consolas", 14), text_color="#dcdcdc", fg_color="#1e1e1e")
        tb.pack(fill="both", expand=True)
        
        inner = tb._textbox
        inner.tag_config("alert", foreground="#ff5252")
        inner.tag_config("warning", foreground="#ffa726")
        inner.tag_config("header", foreground="#00A0D6", font=("Consolas", 14, "bold"))
        
        capture_mode = False
        for line in text.splitlines():
            if ">>>START" in line: break
            tag = None
            if "---" in line and not capture_mode: tag = "header"
            if "[Content Attribution" in line: continue
            elif "[HIDDEN" in line or "[SPEAKER" in line:
                capture_mode = True
                inner.insert("end", "\n"+"="*60+"\n", "warning")
                inner.insert("end", "⚠️ HIDDEN CONTENT:\n", "warning")
                continue
            elif capture_mode:
                if "---" in line:
                    capture_mode = False
                    inner.insert("end", "\n")
                    tag = "header"
                elif ">>" in line:
                    inner.insert("end", f" • {line.replace('>>','').strip()}\n", "warning")
                    continue
            elif "[ALERT]" in line or "SYNTHETIC" in line or "[THREAT]" in line:
                tag = "alert"
            inner.insert("end", line+"\n", tag)
        tb.configure(state="disabled")

    def _create_author_tab(self, text):
        tab = self.tabview.add("Authors & Timeline")
        tb = ctk.CTkTextbox(tab, font=("Consolas", 14), text_color="#dcdcdc", fg_color="#1e1e1e")
        tb.pack(fill="both", expand=True)
        
        inner = tb._textbox
        inner.tag_config("header", foreground="#00A0D6", font=("Consolas", 14, "bold"))
        inner.tag_config("author", foreground="#00A0D6", font=("Segoe UI", 14, "bold"))
        
        parsing_script = False
        for line in text.splitlines():
            if ">>>START_SCRIPT_VIEW<<<" in line:
                parsing_script = True
                continue
            if not parsing_script:
                tag = "header" if "---" in line or "[Content" in line or "[Volume" in line or "[Timeline" in line else None
                inner.insert("end", line+"\n", tag)
            else:
                if "|||" in line:
                    try:
                        author, t = line.split("|||", 1)
                        inner.insert("end", f"{author}\n", "author")
                        inner.insert("end", f"{t}\n\n")
                    except: pass
        tb.configure(state="disabled")

    def _has_thumbnail(self, filepath):
        """Check if file has a thumbnail without creating the tab."""
        try:
            l = DocLoader(filepath)
            if l.load():
                has_thumb = any("thumbnail" in f.lower() for f in l.zip_ref.namelist())
                l.close()
                return has_thumb
        except:
            return False
        return False
    
    def _create_thumbnail_tab(self, filepath):
        tab = self.tabview.add("Thumbnail")
        try:
            l = DocLoader(filepath)
            if l.load():
                tf = next((f for f in l.zip_ref.namelist() if "thumbnail" in f.lower()), None)
                if tf:
                    data = l.zip_ref.read(tf)
                    img = Image.open(io.BytesIO(data))
                    img.thumbnail((800,600))
                    ci = ctk.CTkImage(img, size=img.size)
                    ctk.CTkLabel(tab, image=ci, text="").pack(expand=True)
                l.close()
        except: pass