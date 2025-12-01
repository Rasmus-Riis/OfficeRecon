import re
from utils.helpers import NS, log_info, log_warning, log_success, log_danger

class PPTXDeepAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.author_map = {} 

    def run(self):
        print("\n--- PowerPoint Specific Forensics ---")
        self._scan_revisions()
        self._scan_view_props()
        self._check_hidden_slides()
        
        # Authors & Content
        self._build_author_map() 
        self._scan_comments_content()
        self._scan_speaker_notes_content() # <--- NEW

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
        tree = self.loader.get_xml_tree('ppt/commentAuthors.xml')
        if not tree: return
        for a in tree.xpath('//*[local-name()="cmAuthor"]'):
            a_id = a.get('id')
            name = a.get('name', 'Unknown')
            initials = a.get('initials', '')
            if a_id: self.author_map[a_id] = f"{name} ({initials})"

    def _scan_comments_content(self):
        comment_files = [f for f in self.loader.zip_ref.namelist() if f.startswith('ppt/comments/comment')]
        if not comment_files: return

        log_info(f"Found {len(comment_files)} Comment Files. Extracting content...")
        for cf in comment_files:
            tree = self.loader.get_xml_tree(cf)
            if not tree: continue
            for c in tree.xpath('//*[local-name()="cm"]'):
                author_id = c.get('authorId')
                dt = c.get('dt', 'N/A')
                text = "".join([t.text for t in c.xpath('.//*[local-name()="t"]') if t.text])
                author = self.author_map.get(author_id, f"Unknown (ID: {author_id})")
                print(f"   -> [{dt}] {author}: \"{text}\"")

    def _scan_speaker_notes_content(self):
        """Extracts text from notes slides."""
        notes_files = [f for f in self.loader.zip_ref.namelist() if f.startswith('ppt/notesSlides/notesSlide')]
        if not notes_files: return

        found_notes = []
        for nf in notes_files:
            try:
                tree = self.loader.get_xml_tree(nf)
                if not tree: continue
                # Text in notes is inside <a:t> (drawingml text)
                # We use local-name to avoid namespace headaches
                text_nodes = tree.xpath('//*[local-name()="t"]')
                full_text = " ".join([t.text.strip() for t in text_nodes if t.text])
                if full_text: found_notes.append(full_text)
            except: pass

        if found_notes:
            log_danger(f"EXTRACTED {len(found_notes)} SPEAKER NOTES:")
            # Tag for GUI parsing
            print("[SPEAKER NOTES DATA]:")
            for note in found_notes:
                print(f" >> {note}")

    def _scan_view_props(self):
        pres = self.loader.get_xml_tree('ppt/presProps.xml')
        if pres:
            if pres.xpath('//*[local-name()="loop"]'):
                print("   -> Presentation is set to Loop continuously.")
            if pres.xpath('//*[local-name()="laserClr"]'):
                print(f"   -> Custom Laser Pointer Color detected.")

    def _check_hidden_slides(self):
        tree = self.loader.get_xml_tree('docProps/app.xml')
        if not tree: return
        ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
        hidden = tree.xpath('//ep:HiddenSlides', namespaces=ns)
        if hidden and hidden[0].text != "0":
            log_danger(f"HIDDEN SLIDES DETECTED: {hidden[0].text}")