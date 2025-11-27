import re
from utils.helpers import NS, log_info, log_warning, log_success, log_danger

class PPTXDeepAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.author_map = {} # {id: "Name (Initials)"}

    def run(self):
        print("\n--- PowerPoint Specific Forensics ---")
        self._scan_revisions()
        self._scan_view_props()
        self._check_hidden_content()
        
        # Map authors first, then get content
        self._build_author_map() 
        self._scan_comments_content()

    def _scan_revisions(self):
        tree = self.loader.get_xml_tree('ppt/revisionInfo.xml')
        if not tree: return

        clients = tree.xpath('//*[local-name()="client"]')
        if clients:
            log_warning(f"Found {len(clients)} Editing Sessions (Revision History):")
            print(f"   {'Timestamp':<25} | {'Client GUID (Machine ID)'}")
            print("   " + "-"*65)
            for c in clients:
                dt = c.get('dt', 'N/A')
                guid = c.get('id', 'N/A')
                ver = c.get('v', '?')
                print(f"   {dt:<25} | {guid} (v{ver})")

    def _build_author_map(self):
        """Builds a dictionary of ID -> Name for comment attribution."""
        tree = self.loader.get_xml_tree('ppt/commentAuthors.xml')
        if not tree: return

        authors = tree.xpath('//*[local-name()="cmAuthor"]')
        for a in authors:
            a_id = a.get('id')
            name = a.get('name', 'Unknown')
            initials = a.get('initials', '')
            if a_id:
                self.author_map[a_id] = f"{name} ({initials})"

    def _scan_comments_content(self):
        """Scans all comment files and links them to authors."""
        # Find all comment files (usually ppt/comments/comment1.xml, etc.)
        comment_files = [f for f in self.loader.zip_ref.namelist() if f.startswith('ppt/comments/comment')]
        
        if not comment_files:
            return

        log_info(f"Found {len(comment_files)} Comment Files. extracting content...")
        
        for cf in comment_files:
            tree = self.loader.get_xml_tree(cf)
            if not tree: continue
            
            # Find comments
            comments = tree.xpath('//*[local-name()="cm"]')
            for c in comments:
                author_id = c.get('authorId')
                dt = c.get('dt', 'N/A')
                
                # Extract text
                text_parts = c.xpath('.//*[local-name()="t"]')
                text = "".join([t.text for t in text_parts if t.text])
                
                author_name = self.author_map.get(author_id, f"Unknown (ID: {author_id})")
                
                print(f"   -> [{dt}] {author_name}: \"{text}\"")

    def _scan_view_props(self):
        pres = self.loader.get_xml_tree('ppt/presProps.xml')
        if pres:
            if pres.xpath('//*[local-name()="loop"]'):
                print("   -> Presentation is set to Loop continuously.")
            laser = pres.xpath('//*[local-name()="laserClr"]')
            if laser:
                print(f"   -> Custom Laser Pointer Color detected.")

    def _check_hidden_content(self):
        tree = self.loader.get_xml_tree('docProps/app.xml')
        if not tree: return
        ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
        
        hidden = tree.xpath('//ep:HiddenSlides', namespaces=ns)
        notes = tree.xpath('//ep:Notes', namespaces=ns)
        
        if hidden and hidden[0].text != "0":
            log_danger(f"HIDDEN SLIDES DETECTED: {hidden[0].text}")
            
        if notes and notes[0].text != "0":
            log_info(f"Found {notes[0].text} Speaker Notes.")