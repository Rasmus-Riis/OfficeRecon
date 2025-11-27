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
            "title": "", "type": "ERR",
            "size": f"{os.path.getsize(filepath)/1024:.1f} KB",
            "verdict": "Unknown", "generator": "",
            
            # Times
            "fs_created": "", "fs_modified": "", "fs_accessed": "",
            "zip_modified": "", "meta_created": "", "meta_modified": "",
            
            # Meta
            "author": "", "last_mod_by": "", "printed": "", 
            "status": "", "category": "", "template": "", 
            "rev_count": "0", "edit_time": "0",
            
            # Stats
            "pages": "0", "words": "0", "paragraphs": "0", 
            "slides": "0", 
            
            # Forensics
            "rsid_count": "0", "platform": "Unknown", 
            "threats": [], "media_count": "0", "exif": "No",
            "leaked_user": "", "hidden_text": "",
            "ppt_rev_dates": "" 
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

            # 3. Metadata (Unified & Specific)
            if loader.file_type in ['docx', 'xlsx', 'pptx']:
                self._analyze_ooxml_core(loader, data)
            
            if loader.file_type == 'docx':
                self._analyze_word_specifics(loader, data)
            elif loader.file_type == 'pptx':
                self._analyze_ppt_deep(loader, data) # <--- UPDATED DEEP SCANNER
            elif loader.file_type == 'odt':
                self._analyze_odt(loader, data)

            # 4. Checks
            self._check_universal(loader, data)
            self._scan_embeddings(loader, data)
            
            loader.close()
        except: pass
        return data

    def _analyze_ooxml_core(self, loader, data):
        """Extracts standard Core and App properties using robust namespaces."""
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

    def _analyze_word_specifics(self, loader, data):
        try:
            m = int(data["edit_time"].replace(" min", ""))
            w = int(data["words"])
            if m <= 1 and w > 500: data["threats"].append("HIGH VELOCITY")
        except: pass

        settings = loader.get_xml_tree('word/settings.xml')
        if settings:
            rsids = settings.xpath('//w:rsid', namespaces=NS)
            data["rsid_count"] = str(len(rsids))
            if len(rsids) < 5: data["verdict"] = "SYNTHETIC"
            elif len(rsids) > 100: data["verdict"] = "ORGANIC"
            else: data["verdict"] = "MIXED"
        
        doc = loader.get_xml_tree('word/document.xml')
        if doc and doc.xpath("//w:color[@w:val='FFFFFF']", namespaces=NS):
            data["threats"].append("HIDDEN TEXT")

    def _analyze_ppt_deep(self, loader, data):
        """Deep forensic extraction for PPTX."""
        # 1. App Properties (Slides & Hidden Slides)
        app = loader.get_xml_tree('docProps/app.xml')
        if app:
            data["slides"] = self._val(app, '//ep:Slides', NS)
            hidden = self._val(app, '//ep:HiddenSlides', NS)
            if hidden and hidden != "0":
                data["threats"].append(f"HIDDEN SLIDES ({hidden})")

        # 2. Revision History (revisionInfo.xml)
        # This file contains Client GUIDs and timestamps of edits
        rev = loader.get_xml_tree('ppt/revisionInfo.xml')
        if rev:
            # Use local-name() to ignore messy p14/p15 namespaces
            clients = rev.xpath('//*[local-name()="client"]')
            rev_dates = []
            for c in clients:
                dt = c.get('dt')
                if dt: rev_dates.append(self._fmt_iso(dt))
            
            if rev_dates:
                # Store the latest revision date found here if meta is missing
                data["ppt_rev_dates"] = rev_dates[-1] 
                data["threats"].append("REV-HISTORY")
                
                # If core.xml didn't give us a modified date, use this one
                if not data["meta_modified"]:
                    data["meta_modified"] = rev_dates[-1]

        # 3. Comment Authors (commentAuthors.xml)
        # Often contains names not listed in core.xml
        authors = loader.get_xml_tree('ppt/commentAuthors.xml')
        if authors:
            author_list = []
            for a in authors.xpath('//*[local-name()="cmAuthor"]'):
                name = a.get('name')
                if name: author_list.append(name)
            
            if author_list:
                data["threats"].append("COMMENTS")
                # If we haven't found a leaked user yet, use the first comment author
                if not data["leaked_user"]:
                    data["leaked_user"] = f"Commenter: {author_list[0]}"

        # 4. Presentation Properties (presProps.xml)
        # Detects show settings (Loop, Kiosk mode)
        pres = loader.get_xml_tree('ppt/presProps.xml')
        if pres:
            if pres.xpath('//*[local-name()="loop"]'):
                data["status"] += " [Loop]"
            if pres.xpath('//*[local-name()="kiosk"]'):
                data["status"] += " [Kiosk]"

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
        # Check ANY folder for vbaProject.bin
        if any(f.endswith('vbaProject.bin') for f in loader.zip_ref.namelist()):
            data["threats"].append("MACROS")
        
        # Thumbnail check (insensitive)
        if any('thumbnail' in f.lower() for f in loader.zip_ref.namelist()):
            data["threats"].append("THUMBNAIL")

        # Template Injection (Docx)
        if loader.file_type == 'docx':
            rels = loader.get_xml_tree('word/_rels/document.xml.rels')
            if rels:
                targets = rels.xpath(f"//rel:Relationship[@TargetMode='External']", namespaces=NS)
                for t in targets:
                    if "attachedTemplate" in t.get('Type', ''):
                        data["threats"].append("INJECTION")
                        break

        media = [f for f in loader.zip_ref.namelist() if f.startswith(('word/media/', 'xl/media/', 'ppt/media/', 'Pictures/'))]
        data["media_count"] = str(len(media))
        if media: data["exif"] = "Yes"

    def _scan_embeddings(self, loader, data):
        emb_files = [f for f in loader.zip_ref.namelist() if f.startswith(('word/embeddings/', 'xl/embeddings/', 'ppt/embeddings/'))]
        if not emb_files: return
        user_pat = re.compile(rb'(?:Users|home)[\\/]([^\\/]+)[\\/]')
        for ef in emb_files:
            try:
                content = loader.zip_ref.read(ef)
                match = user_pat.search(content)
                if match:
                    user = match.group(1).decode('utf-8', errors='ignore')
                    if len(user) < 20 and user.lower() not in ['admin', 'default', 'public']:
                        if not data["leaked_user"]: # Don't overwrite if we found one in comments
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