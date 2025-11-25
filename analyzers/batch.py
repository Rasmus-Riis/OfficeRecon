import os
import zipfile
import re
import datetime
from core.loader import DocLoader
from utils.helpers import NS

class BatchAnalyzer:
    def analyze(self, filepath):
        data = {
            "filename": os.path.basename(filepath),
            "title": "",
            "type": "ERR",
            "size": f"{os.path.getsize(filepath)/1024:.1f} KB",
            "verdict": "Unknown",
            "generator": "",
            
            # Times
            "fs_created": "", "fs_modified": "", "fs_accessed": "",
            "zip_modified": "", "meta_created": "", "meta_modified": "",
            
            # Meta
            "author": "", "last_mod_by": "", "printed": "", 
            "status": "", "category": "", "template": "", 
            "rev_count": "0", "edit_time": "0",
            
            # Stats
            "pages": "0", "words": "0", "paragraphs": "0",
            
            # Forensics
            "rsid_count": "0", "platform": "Unknown", 
            "threats": [], "media_count": "0", "exif": "No",
            "leaked_user": "",
            "hidden_text": "" # <--- NEW FIELD
        }

        # 1. File System
        try:
            stat = os.stat(filepath)
            data["fs_created"] = self._fmt_fs(stat.st_ctime)
            data["fs_modified"] = self._fmt_fs(stat.st_mtime)
            data["fs_accessed"] = self._fmt_fs(stat.st_atime)
        except: pass

        try:
            loader = DocLoader(filepath)
            if not loader.load(): return data
            
            data["type"] = loader.file_type.upper()
            
            # 2. Zip Time
            try:
                latest = max(loader.zip_ref.infolist(), key=lambda x: x.date_time)
                dt = datetime.datetime(*latest.date_time)
                data["zip_modified"] = dt.strftime("%d/%m/%Y %H:%M:%S")
            except: pass

            # 3. Metadata
            if loader.file_type == 'docx':
                self._analyze_docx(loader, data)
            elif loader.file_type == 'odt':
                self._analyze_odt(loader, data)

            # 4. Universal
            self._check_universal(loader, data)
            
            # 5. User Leaks
            self._scan_embeddings(loader, data)
            
            loader.close()
        except: pass
        return data

    def _analyze_docx(self, loader, data):
        core = loader.get_xml_tree('docProps/core.xml')
        if core:
            data["title"] = self._val(core, '//dc:title', NS)
            data["author"] = self._val(core, '//dc:creator', NS)
            data["last_mod_by"] = self._val(core, '//cp:lastModifiedBy', NS)
            data["meta_created"] = self._fmt_iso(self._val(core, '//dcterms:created', NS))
            data["meta_modified"] = self._fmt_iso(self._val(core, '//dcterms:modified', NS))
            data["printed"] = self._fmt_iso(self._val(core, '//cp:lastPrinted', NS))
            data["status"] = self._val(core, '//cp:contentStatus', NS)
            data["category"] = self._val(core, '//cp:category', NS)
            data["rev_count"] = self._val(core, '//cp:revision', NS)

        app = loader.get_xml_tree('docProps/app.xml')
        if app:
            data["template"] = self._val(app, '//ep:Template', NS)
            data["generator"] = self._val(app, '//ep:Application', NS)
            data["edit_time"] = self._val(app, '//ep:TotalTime', NS) + " min"
            data["pages"] = self._val(app, '//ep:Pages', NS)
            data["words"] = self._val(app, '//ep:Words', NS)
            
            app_str = self._val(app, '//ep:Application', NS)
            if "Macintosh" in app_str: data["platform"] = "MacOS"
            elif "Windows" in app_str: data["platform"] = "Windows"

            try:
                m = int(self._val(app, '//ep:TotalTime', NS) or 0)
                w = int(self._val(app, '//ep:Words', NS) or 0)
                if m <= 1 and w > 500: data["threats"].append("HIGH VELOCITY")
            except: pass

        settings = loader.get_xml_tree('word/settings.xml')
        if settings:
            rsids = settings.xpath('//w:rsid', namespaces=NS)
            data["rsid_count"] = str(len(rsids))
            if len(rsids) < 5: data["verdict"] = "SYNTHETIC"
            elif len(rsids) > 100: data["verdict"] = "ORGANIC"
            else: data["verdict"] = "MIXED"
            
        # --- ROBUST HIDDEN TEXT CHECK (Copied & Adapted from Threats.py) ---
        doc = loader.get_xml_tree('word/document.xml')
        if doc:
            hidden_snippet = self._find_hidden_text(doc)
            if hidden_snippet:
                data["threats"].append("HIDDEN TEXT")
                data["hidden_text"] = hidden_snippet # Save the content

    def _find_hidden_text(self, tree):
        """Scans for White-on-White but ignores valid uses (shading/styles). Returns first match."""
        color_nodes = tree.xpath("//w:color[@w:val='FFFFFF']", namespaces=NS)
        for color_node in color_nodes:
            rPr = color_node.getparent()
            if rPr is None: continue
            is_visible = False
            
            # 1. Run Highlight/Shading
            if rPr.find(f"{{{NS['w']}}}highlight") is not None: is_visible = True
            shd = rPr.find(f"{{{NS['w']}}}shd")
            if shd is not None and shd.get(f"{{{NS['w']}}}fill", "auto").lower() not in ['auto', 'ffffff']: is_visible = True

            # 2. Paragraph Shading/Style
            if not is_visible:
                run = rPr.getparent()
                para = run.getparent() if run is not None else None
                if para is not None:
                    pPr = para.find(f"{{{NS['w']}}}pPr")
                    if pPr is not None:
                        p_shd = pPr.find(f"{{{NS['w']}}}shd")
                        if p_shd is not None and p_shd.get(f"{{{NS['w']}}}fill", "auto").lower() not in ['auto', 'ffffff']: is_visible = True
                        # Check Style
                        p_style = pPr.find(f"{{{NS['w']}}}pStyle")
                        if p_style is not None and p_style.get(f"{{{NS['w']}}}val", "").lower() != "normal": is_visible = True

            # 3. Table Cell
            if not is_visible:
                for ancestor in rPr.iterancestors():
                    if ancestor.tag.endswith('tc'):
                        tcPr = ancestor.find(f"{{{NS['w']}}}tcPr")
                        if tcPr is not None:
                            tc_shd = tcPr.find(f"{{{NS['w']}}}shd")
                            if tc_shd is not None and tc_shd.get(f"{{{NS['w']}}}fill", "auto").lower() not in ['auto', 'ffffff']: is_visible = True
                        break

            # 4. Drawings
            if not is_visible:
                for ancestor in rPr.iterancestors():
                    if ancestor.tag.endswith('drawing') or ancestor.tag.endswith('txbxContent'): is_visible = True; break

            if not is_visible:
                run = rPr.getparent()
                text_node = run.find(f"{{{NS['w']}}}t")
                if text_node is not None and text_node.text:
                    return text_node.text.strip() # Return first hit
        return ""

    def _analyze_odt(self, loader, data):
        meta = loader.get_xml_tree('meta.xml')
        if meta:
            ns = {'meta': 'urn:oasis:names:tc:opendocument:xmlns:meta:1.0', 'dc': 'http://purl.org/dc/elements/1.1/'}
            data["title"] = self._val(meta, '//dc:title', ns)
            data["meta_created"] = self._fmt_iso(self._val(meta, '//meta:creation-date', ns))
            data["meta_modified"] = self._fmt_iso(self._val(meta, '//dc:date', ns))
            data["author"] = self._val(meta, '//dc:creator', ns)
            data["generator"] = self._val(meta, '//meta:generator', ns)

    def _check_universal(self, loader, data):
        if 'word/vbaProject.bin' in loader.zip_ref.namelist(): data["threats"].append("MACROS")
        if 'docProps/thumbnail.jpeg' in loader.zip_ref.namelist(): data["threats"].append("THUMBNAIL")

        if loader.file_type == 'docx':
            rels = loader.get_xml_tree('word/_rels/document.xml.rels')
            if rels:
                targets = rels.xpath(f"//rel:Relationship[@TargetMode='External']", namespaces=NS)
                for t in targets:
                    if "attachedTemplate" in t.get('Type', ''):
                        data["threats"].append("INJECTION")
                        break

        media = [f for f in loader.zip_ref.namelist() if f.startswith('word/media/') or f.startswith('Pictures/')]
        data["media_count"] = str(len(media))
        if media: data["exif"] = "Yes"

    def _scan_embeddings(self, loader, data):
        emb_files = [f for f in loader.zip_ref.namelist() if f.startswith('word/embeddings/')]
        if not emb_files: return
        user_pat = re.compile(rb'(?:Users|home)[\\/]([^\\/]+)[\\/]')
        for ef in emb_files:
            try:
                content = loader.zip_ref.read(ef)
                match = user_pat.search(content)
                if match:
                    user = match.group(1).decode('utf-8', errors='ignore')
                    if len(user) < 20 and user.lower() not in ['admin', 'default', 'public']:
                        data["leaked_user"] = user
                        data["threats"].append("USER LEAK")
                        return
            except: pass

    def _val(self, tree, xpath, ns):
        try:
            el = tree.xpath(xpath, namespaces=ns)
            return el[0].text if el and el[0].text else ""
        except: return ""

    def _fmt_fs(self, ts):
        try: return datetime.datetime.fromtimestamp(ts).astimezone().strftime("%d/%m/%Y %H:%M:%S %z")
        except: return ""

    def _fmt_iso(self, iso):
        if not iso: return ""
        try:
            if iso.endswith("Z"):
                dt = datetime.datetime.strptime(iso.replace("Z", ""), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
                return dt.strftime("%d/%m/%Y %H:%M:%S %z")
            if "." in iso: iso = iso.split(".")[0] + iso[-6:] if "+" in iso[-6:] else iso.split(".")[0]
            dt = datetime.datetime.fromisoformat(iso)
            return dt.strftime("%d/%m/%Y %H:%M:%S %z") if dt.tzinfo else dt.strftime("%d/%m/%Y %H:%M:%S")
        except: return iso.replace("T", " ")