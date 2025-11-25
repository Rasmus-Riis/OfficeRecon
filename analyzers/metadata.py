import os
import datetime
import stat
from utils.helpers import log_info, log_warning, log_danger, log_success, NS

class MetadataAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.stats = {}

    def run(self):
        print("\n--- Deep Metadata Analysis ---")
        self._analyze_file_system()  
        
        if self.loader.file_type == 'docx':
            self._parse_core_props()     
            self._parse_app_props()
            self._analyze_velocity()
            self._parse_custom_props()
            self._parse_doc_settings()
        elif self.loader.file_type == 'odt':
            self._parse_odt_meta() # <--- NEW ODT SUPPORT
        else:
            print("   [!] Unknown file type. Skipping internal metadata.")

    def _analyze_file_system(self):
        print(f"{'[File System Properties]':<25}")
        try:
            path = self.loader.filepath
            file_stat = os.stat(path)
            size_mb = file_stat.st_size / (1024 * 1024)
            print(f"  {'File Size':<20}: {size_mb:.2f} MB")
            
            ts_mod = datetime.datetime.fromtimestamp(file_stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            print(f"  {'Disk Modified':<20}: {ts_mod}")
            
            # Attributes
            attributes = []
            if hasattr(file_stat, 'st_file_attributes'):
                attrs = file_stat.st_file_attributes
                if attrs & stat.FILE_ATTRIBUTE_HIDDEN: attributes.append("HIDDEN")
                if attrs & stat.FILE_ATTRIBUTE_SYSTEM: attributes.append("SYSTEM")
            
            if attributes:
                log_warning(f"Attributes: {', '.join(attributes)}")

        except Exception as e:
            print(f"  [Error: {e}]")

    def _parse_odt_meta(self):
        """Parses OpenDocument meta.xml"""
        tree = self.loader.get_xml_tree('meta.xml')
        if not tree: return

        # ODT Namespaces
        odt_ns = {
            'office': 'urn:oasis:names:tc:opendocument:xmlns:office:1.0',
            'meta': 'urn:oasis:names:tc:opendocument:xmlns:meta:1.0',
            'dc': 'http://purl.org/dc/elements/1.1/'
        }

        print(f"\n{'[ODT Internal Metadata]':<25}")
        
        # Mapping
        fields = {
            'Generator': '//meta:generator',
            'Title': '//dc:title',
            'Description': '//dc:description',
            'Creator': '//dc:creator',
            'Created': '//meta:creation-date',
            'Modified': '//dc:date',
            'Editing Cycles': '//meta:editing-cycles',
            'Edit Time': '//meta:editing-duration'
        }

        for label, xpath in fields.items():
            val = self._get_text(tree, xpath, odt_ns)
            if val:
                print(f"  {label:<20}: {val}")

    # --- DOCX METHODS (Unchanged) ---
    def _parse_core_props(self):
        tree = self.loader.get_xml_tree('docProps/core.xml')
        if not tree: return
        ns = {'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
              'dc': 'http://purl.org/dc/elements/1.1/', 'dcterms': 'http://purl.org/dc/terms/'}
        print(f"\n{'[Internal Core Properties]':<25}")
        fields = {'Title': '//dc:title', 'Author': '//dc:creator', 'Last Mod By': '//cp:lastModifiedBy', 
                  'Created': '//dcterms:created', 'Modified': '//dcterms:modified', 'Revision': '//cp:revision'}
        for l, x in fields.items():
            val = self._get_text(tree, x, ns)
            if val: print(f"  {l:<20}: {val}")

    def _parse_app_props(self):
        tree = self.loader.get_xml_tree('docProps/app.xml')
        if not tree: return
        ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
        print(f"\n{'[Extended App Stats]':<25}")
        self.stats['time'] = int(self._get_text(tree, '//ep:TotalTime', ns) or 0)
        self.stats['words'] = int(self._get_text(tree, '//ep:Words', ns) or 0)
        print(f"  Total Edit Time     : {self.stats['time']} minutes")
        print(f"  Word Count          : {self.stats['words']}")
        print(f"  Application         : {self._get_text(tree, '//ep:Application', ns)}")

    def _analyze_velocity(self):
        m = self.stats.get('time', 0)
        w = self.stats.get('words', 0)
        if w < 100: return
        print(f"\n{'[Forensic Velocity Check]':<25}")
        if m <= 1 and w > 500: log_danger("IMPOSSIBLE VELOCITY: >500 words in <1 min.")
        elif m > 0:
            wpm = w/m
            print(f"  Speed: {wpm:.1f} WPM")
            if wpm > 150: log_warning("HIGH VELOCITY: >150 WPM.")
            else: log_success("ORGANIC VELOCITY.")

    def _parse_custom_props(self):
        tree = self.loader.get_xml_tree('docProps/custom.xml')
        if not tree: return
        ns = {'cp': 'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties'}
        props = tree.xpath('//cp:property', namespaces=ns)
        if props:
            print(f"\n{'[Custom Properties]':<25}")
            for p in props:
                print(f"  {p.get('name'):<20}: {p[0].text if len(p)>0 else 'Empty'}")

    def _parse_doc_settings(self):
        tree = self.loader.get_xml_tree('word/settings.xml')
        if not tree: return
        if tree.xpath('//w:trackRevisions', namespaces=NS):
            print(f"\n[Settings]")
            log_info("Track Changes is ENABLED.")

    def _get_text(self, tree, xpath, ns):
        elements = tree.xpath(xpath, namespaces=ns)
        return elements[0].text if elements and elements[0].text else None