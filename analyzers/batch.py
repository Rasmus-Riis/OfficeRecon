import os
import zipfile
import re
import datetime
import hashlib
from core.loader import DocLoader
from utils.helpers import NS

class BatchAnalyzer:
    def analyze(self, filepath):
        md5_val = self._get_md5(filepath)

        data = {
            "filename": os.path.basename(filepath),
            "md5": md5_val,
            "title": "", "type": "ERR",
            "size": f"{os.path.getsize(filepath)/1024:.1f} KB",
            "verdict": "Unknown", "generator": "",
            "fs_created": "", "fs_modified": "", "fs_accessed": "",
            "zip_modified": "", "meta_created": "", "meta_modified": "",
            "author": "", "last_mod_by": "", "printed": "", 
            "status": "", "category": "", "template": "", 
            "rev_count": "0", "edit_time": "0",
            "pages": "0", "words": "0", "paragraphs": "0", "slides": "0", 
            "rsid_count": "0", "platform": "Unknown", 
            "threats": [], "media_count": "0", "exif": "No",
            "leaked_user": "", "hidden_text": "",
            "ppt_rev_dates": "",
            "forensic_artifacts": [] 
        }

        try:
            stat = os.stat(filepath)
            data["fs_created"] = self._fmt_fs(stat.st_ctime)
            data["fs_modified"] = self._fmt_fs(stat.st_mtime)
            data["fs_accessed"] = self._fmt_fs(stat.st_atime)
        except: pass

        if self._is_encrypted(filepath):
            data["verdict"] = "LOCKED"
            data["threats"].append("PASSWORD PROTECTED")
            data["forensic_artifacts"] = "File is Encrypted (OLE Container)"
            data["type"] = "OLE/ENC"
            return data 

        try:
            loader = DocLoader(filepath)
            if not loader.load(): 
                data["forensic_artifacts"] = ""
                return data
            
            data["type"] = loader.file_type.upper()
            try:
                latest = max(loader.zip_ref.infolist(), key=lambda x: x.date_time)
                dt = datetime.datetime(*latest.date_time)
                data["zip_modified"] = dt.strftime("%d/%m/%Y %H:%M:%S")
            except: pass

            if loader.file_type in ['docx', 'xlsx', 'pptx']: self._analyze_ooxml_core(loader, data)
            if loader.file_type == 'docx': self._analyze_word_specifics(loader, data)
            elif loader.file_type == 'pptx': self._analyze_ppt_deep(loader, data)
            elif loader.file_type == 'odt': self._analyze_odt(loader, data)

            self._check_universal(loader, data)
            self._scan_embeddings(loader, data)
            loader.close()
        except: pass
        
        data["forensic_artifacts"] = " | ".join(data["forensic_artifacts"])
        return data

    def _get_md5(self, filepath):
        try:
            hash_md5 = hashlib.md5()
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""): hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except: return "Error"

    def _is_encrypted(self, filepath):
        try:
            with open(filepath, 'rb') as f: header = f.read(8)
            if header == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
                ext = os.path.splitext(filepath)[1].lower()
                if ext in ['.docx', '.docm', '.xlsx', '.xlsm', '.pptx', '.pptm']: return True
            return False
        except: return False

    def _analyze_ooxml_core(self, loader, data):
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
            if m <= 1 and w > 500: 
                data["threats"].append("HIGH VELOCITY")
                data["forensic_artifacts"].append(f"High Velocity: {w} words in {m} min")
        except: pass
        settings = loader.get_xml_tree('word/settings.xml')
        if settings:
            rsids = settings.xpath('//w:rsid', namespaces=NS)
            data["rsid_count"] = str(len(rsids))
            if len(rsids) < 5: 
                data["verdict"] = "SYNTHETIC"
                data["forensic_artifacts"].append(f"Synthetic RSID Count: {len(rsids)}")
            elif len(rsids) > 100: data["verdict"] = "ORGANIC"
            else: data["verdict"] = "MIXED"
        doc = loader.get_xml_tree('word/document.xml')
        if doc:
            hidden_nodes = doc.xpath("//w:color[@w:val='FFFFFF']", namespaces=NS)
            if hidden_nodes:
                data["threats"].append("HIDDEN TEXT")
                snippets = []
                for node in hidden_nodes[:3]:
                    try:
                        parent_run = node.getparent().getparent()
                        text = "".join(parent_run.xpath(".//w:t/text()", namespaces=NS))
                        if text: snippets.append(text[:20])
                    except: pass
                if snippets: data["forensic_artifacts"].append(f"Hidden: '{', '.join(snippets)}...'")

    def _analyze_ppt_deep(self, loader, data):
        app = loader.get_xml_tree('docProps/app.xml')
        if app:
            data["slides"] = self._val(app, '//ep:Slides', NS)
            hidden = self._val(app, '//ep:HiddenSlides', NS)
            if hidden and hidden != "0":
                data["threats"].append(f"HIDDEN SLIDES ({hidden})")
                data["forensic_artifacts"].append(f"{hidden} Hidden Slides Found")
        rev = loader.get_xml_tree('ppt/revisionInfo.xml')
        if rev:
            clients = rev.xpath('//*[local-name()="client"]')
            rev_dates = []
            for c in clients:
                dt = c.get('dt')
                if dt: rev_dates.append(self._fmt_iso(dt))
            if rev_dates:
                data["ppt_rev_dates"] = rev_dates[-1] 
                data["threats"].append("REV-HISTORY")
                data["forensic_artifacts"].append(f"Rev History: {len(rev_dates)} entries")
                if not data["meta_modified"]: data["meta_modified"] = rev_dates[-1]
        authors = loader.get_xml_tree('ppt/commentAuthors.xml')
        if authors:
            author_list = []
            for a in authors.xpath('//*[local-name()="cmAuthor"]'):
                name = a.get('name')
                if name: author_list.append(name)
            if author_list:
                data["threats"].append("COMMENTS")
                if not data["leaked_user"]: data["leaked_user"] = f"Commenter: {author_list[0]}"
                data["forensic_artifacts"].append(f"Comments by: {', '.join(author_list[:2])}")

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
        if any(f.endswith('vbaProject.bin') for f in loader.zip_ref.namelist()):
            data["threats"].append("MACROS")
            data["forensic_artifacts"].append("VBA Macros Detected")
        if any('thumbnail' in f.lower() for f in loader.zip_ref.namelist()):
            data["threats"].append("THUMBNAIL")
        if loader.file_type == 'docx':
            rels = loader.get_xml_tree('word/_rels/document.xml.rels')
            if rels:
                targets = rels.xpath(f"//rel:Relationship[@TargetMode='External']", namespaces=NS)
                for t in targets:
                    if "attachedTemplate" in t.get('Type', ''):
                        data["threats"].append("INJECTION")
                        data["forensic_artifacts"].append(f"Remote Template: {t.get('Target')}")
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
                        if not data["leaked_user"]:
                            data["leaked_user"] = user
                            data["threats"].append("USER LEAK")
                            data["forensic_artifacts"].append(f"Sys Path User: {user}")
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