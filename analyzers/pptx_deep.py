import re
from utils.helpers import NS, log_info, log_warning, log_success, log_danger

class PPTXDeepAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.author_map = {} 

    def run(self):
        print("\n--- PowerPoint Specific Forensics ---")
        self._scan_metadata()
        self._scan_revisions()
        self._scan_view_props()
        self._check_hidden_slides()
        
        # Authors & Content
        self._build_author_map() 
        self._scan_comments_content()
        self._scan_speaker_notes_content()
        self._scan_slide_masters()
        self._scan_embedded_objects()
        self._check_animations()
        self._scan_custom_properties()

    def _scan_metadata(self):
        """Extract PowerPoint metadata from core and app properties."""
        print(f"\n{'[PPTX Metadata]':<25}")
        
        # Core properties
        core_tree = self.loader.get_xml_tree('docProps/core.xml')
        if core_tree:
            ns = {'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                  'dc': 'http://purl.org/dc/elements/1.1/', 
                  'dcterms': 'http://purl.org/dc/terms/'}
            
            fields = {
                'Title': '//dc:title',
                'Author': '//dc:creator',
                'Last Modified By': '//cp:lastModifiedBy',
                'Created': '//dcterms:created',
                'Modified': '//dcterms:modified',
                'Revision': '//cp:revision',
                'Keywords': '//cp:keywords',
                'Description': '//dc:description',
            }
            
            for label, xpath in fields.items():
                elem = core_tree.xpath(xpath, namespaces=ns)
                if elem and elem[0].text:
                    print(f"  {label:<20}: {elem[0].text}")
        
        # App properties
        app_tree = self.loader.get_xml_tree('docProps/app.xml')
        if app_tree:
            ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
            
            app_fields = {
                'Application': '//ep:Application',
                'App Version': '//ep:AppVersion',
                'Total Edit Time': '//ep:TotalTime',
                'Company': '//ep:Company',
                'Presentation Format': '//ep:PresentationFormat',
            }
            
            for label, xpath in app_fields.items():
                elem = app_tree.xpath(xpath, namespaces=ns)
                if elem and elem[0].text:
                    value = elem[0].text
                    if label == 'Total Edit Time':
                        minutes = int(value) if value.isdigit() else 0
                        value = f"{minutes} minutes"
                    print(f"  {label:<20}: {value}")

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
        total_comments = 0
        for cf in comment_files:
            tree = self.loader.get_xml_tree(cf)
            if not tree: continue
            for c in tree.xpath('//*[local-name()="cm"]'):
                total_comments += 1
                author_id = c.get('authorId')
                dt = c.get('dt', 'N/A')
                text = "".join([t.text for t in c.xpath('.//*[local-name()="t"]') if t.text])
                author = self.author_map.get(author_id, f"Unknown (ID: {author_id})")
                print(f"   -> [{dt}] {author}: \"{text}\"")
        
        if total_comments > 0:
            log_warning(f"Total comments extracted: {total_comments}")

    def _scan_speaker_notes_content(self):
        """Extracts text from notes slides."""
        notes_files = [f for f in self.loader.zip_ref.namelist() if f.startswith('ppt/notesSlides/notesSlide')]
        if not notes_files: 
            log_success("No speaker notes found.")
            return

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
            log_info(f"Extracted {len(found_notes)} speaker notes (normal PowerPoint feature):")
            # Tag for GUI parsing
            print("[SPEAKER NOTES DATA]:")
            for i, note in enumerate(found_notes, 1):
                preview = note[:100] + "..." if len(note) > 100 else note
                print(f" >> Slide {i}: {preview}")

    def _scan_slide_masters(self):
        """Check for hidden content in slide masters and layouts."""
        print(f"\n{'[Slide Masters & Layouts]':<25}")
        
        masters = self.loader.list_files(prefix='ppt/slideMasters/')
        layouts = self.loader.list_files(prefix='ppt/slideLayouts/')
        
        if masters:
            log_info(f"Found {len(masters)} slide master(s)")
        if layouts:
            log_info(f"Found {len(layouts)} slide layout(s)")
        
        # Check for text in masters (potential hidden content)
        hidden_text = []
        for master in masters:
            if master.endswith('.xml'):
                tree = self.loader.get_xml_tree(master)
                if tree:
                    text_nodes = tree.xpath('//*[local-name()="t"]')
                    text = " ".join([t.text.strip() for t in text_nodes if t.text])
                    if text and len(text) > 20:
                        hidden_text.append((master, text[:100]))
        
        if hidden_text:
            log_warning(f"Text found in {len(hidden_text)} slide master(s) (potential hidden content)")

    def _scan_embedded_objects(self):
        """Detect embedded objects and OLE objects."""
        print(f"\n{'[Embedded Objects]':<25}")
        
        # Check for OLE objects
        embedded = self.loader.list_files(prefix='ppt/embeddings/')
        
        if embedded:
            log_warning(f"Found {len(embedded)} embedded object(s):")
            for obj in embedded[:5]:
                obj_name = obj.split('/')[-1]
                print(f"  -> {obj_name}")
            if len(embedded) > 5:
                print(f"  -> ... and {len(embedded) - 5} more")
        else:
            log_success("No embedded objects detected.")

    def _check_animations(self):
        """Check for slide animations (can be used to hide malicious content)."""
        print(f"\n{'[Animations]':<25}")
        
        slides = self.loader.list_files(prefix='ppt/slides/slide', suffix='.xml')
        slides_with_animations = []
        
        for slide in slides:
            tree = self.loader.get_xml_tree(slide)
            if tree:
                # Check for animation timing
                animations = tree.xpath('//*[local-name()="timing"]')
                if animations:
                    slide_num = slide.split('slide')[-1].replace('.xml', '')
                    slides_with_animations.append(slide_num)
        
        if slides_with_animations:
            log_info(f"Animations detected in {len(slides_with_animations)} slide(s): {', '.join(slides_with_animations[:10])}")
        else:
            log_success("No animations detected.")

    def _scan_custom_properties(self):
        """Extract custom document properties."""
        tree = self.loader.get_xml_tree('docProps/custom.xml')
        if not tree:
            return
        
        print(f"\n{'[Custom Properties]':<25}")
        
        ns = {'cp': 'http://schemas.openxmlformats.org/officeDocument/2006/custom-properties',
              'vt': 'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'}
        
        props = tree.xpath('//cp:property', namespaces=ns)
        
        if props:
            for prop in props:
                name = prop.get('name', 'Unknown')
                value_elem = prop.xpath('./vt:lpwstr | ./vt:i4 | ./vt:bool | ./vt:filetime', namespaces=ns)
                value = value_elem[0].text if value_elem and value_elem[0].text else 'N/A'
                print(f"  {name:<20}: {value}")
        else:
            log_success("No custom properties found.")

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