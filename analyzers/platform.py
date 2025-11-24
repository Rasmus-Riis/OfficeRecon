import re
from utils.helpers import NS, log_info, log_warning, log_danger, log_success

class PlatformAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.mac_indicators = []
        self.windows_indicators = []

    def run(self):
        print("\n--- Operating System Fingerprinting ---")
        
        # Run checks
        self._check_app_metadata()
        self._check_zip_artifacts()
        self._check_file_paths()
        self._check_fonts()
        
        # Verdict
        if self.mac_indicators:
            log_warning(f"Mac OS detected ({len(self.mac_indicators)} evidence points):")
            for ind in self.mac_indicators:
                print(f"   -> {ind}")
        elif self.windows_indicators:
            log_info("File appears to be created on a standard Windows environment.")
        else:
            print("   -> No specific OS fingerprints found.")

    def _check_app_metadata(self):
        """Checks docProps/app.xml for the software that created the file."""
        tree = self.loader.get_xml_tree('docProps/app.xml')
        if not tree: return

        # 1. Check Application Name
        app_node = tree.find('.//ep:Application', namespaces=NS)
        if app_node is not None and app_node.text:
            app_text = app_node.text
            if "Macintosh" in app_text or "Mac" in app_text:
                self.mac_indicators.append(f"Metadata explicitly claims: '{app_text}'")
            elif "Windows" in app_text: # Rare, usually just says "Microsoft Office Word"
                self.windows_indicators.append(f"Metadata claims: '{app_text}'")

    def _check_zip_artifacts(self):
        """Scans the raw ZIP structure for hidden OS files."""
        file_list = self.loader.zip_ref.namelist()
        
        # Mac Artifacts
        if "__MACOSX/" in str(file_list): # Folder check
            self.mac_indicators.append("Found '__MACOSX' hidden resource folder (Zip artifact).")
        
        ds_store = [f for f in file_list if ".DS_Store" in f]
        if ds_store:
            self.mac_indicators.append(f"Found {len(ds_store)} '.DS_Store' finder files.")

    def _check_file_paths(self):
        """Scans relationship files for absolute path structures."""
        # Look at all relationship files (document.xml.rels, etc.)
        rel_files = [f for f in self.loader.zip_ref.namelist() if f.endswith('.rels')]
        
        # Regex for Mac paths: starts with /Users/
        mac_path_regex = re.compile(r'file:///Users/[^"]+')
        # Regex for Windows paths: Drive letter C:\ or D:\
        win_path_regex = re.compile(r'file:///[a-zA-Z]:\\')

        for rel_file in rel_files:
            try:
                xml = self.loader.zip_ref.read(rel_file).decode('utf-8', errors='ignore')
                
                if mac_path_regex.search(xml):
                    match = mac_path_regex.search(xml).group(0)
                    self.mac_indicators.append(f"Unix/Mac absolute path found in relationships: {match}")
                
                if win_path_regex.search(xml):
                    self.windows_indicators.append("Windows drive letter paths detected.")
            except:
                continue

    def _check_fonts(self):
        """Checks fontTable for Apple-specific system fonts."""
        tree = self.loader.get_xml_tree('word/fontTable.xml')
        if not tree: return

        # Fonts that strongly imply a Mac creator when they appear as defaults
        mac_fonts = {'Geneva', 'Monaco', 'New York', 'Helvetica Neue', 'Lucida Grande'}
        
        fonts = tree.xpath('//w:font', namespaces=NS)
        for font in fonts:
            name = font.get(f"{{{NS['w']}}}name")
            if name and name in mac_fonts:
                self.mac_indicators.append(f"Reference to Apple system font: '{name}'")