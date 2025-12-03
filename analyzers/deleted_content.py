from utils.helpers import NS, log_info, log_warning, log_success, log_danger
import os

class DeletedContentAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.orphaned_media = []
        self.orphaned_xml = []

    def run(self):
        print("\n--- Deleted Content Recovery ---")
        self._find_orphaned_media()
        self._find_orphaned_xml()
        self._report_findings()

    def _find_orphaned_media(self):
        """Find media files in the archive that aren't referenced in any relationship file."""
        # Get all media files
        media_files = [f for f in self.loader.zip_ref.namelist() 
                      if f.startswith('word/media/') and not f.endswith('/')]
        
        if not media_files:
            return
        
        # Get all relationship files
        rel_files = [f for f in self.loader.zip_ref.namelist() if f.endswith('.rels')]
        
        # Build set of referenced media
        referenced_media = set()
        for rel_file in rel_files:
            tree = self.loader.get_xml_tree(rel_file)
            if not tree:
                continue
            
            relationships = tree.xpath('//rel:Relationship', namespaces=NS)
            for rel in relationships:
                target = rel.get('Target', '')
                if 'media/' in target:
                    # Normalize path
                    if target.startswith('../'):
                        target = target[3:]
                    if not target.startswith('word/'):
                        target = 'word/' + target
                    referenced_media.add(target)
        
        # Find orphans
        for media_file in media_files:
            if media_file not in referenced_media:
                size = self.loader.zip_ref.getinfo(media_file).file_size
                self.orphaned_media.append({
                    'path': media_file,
                    'size': size,
                    'name': os.path.basename(media_file)
                })

    def _find_orphaned_xml(self):
        """Find XML parts that aren't properly linked."""
        # Get all XML files in word/
        xml_files = [f for f in self.loader.zip_ref.namelist() 
                    if f.startswith('word/') and f.endswith('.xml') and '/' not in f[5:-4]]
        
        # Expected files
        expected = [
            'word/document.xml', 'word/styles.xml', 'word/settings.xml',
            'word/webSettings.xml', 'word/fontTable.xml', 'word/numbering.xml'
        ]
        
        # Check content types
        content_types_tree = self.loader.get_xml_tree('[Content_Types].xml')
        if content_types_tree:
            overrides = content_types_tree.xpath('//ct:Override', namespaces={'ct': 'http://schemas.openxmlformats.org/package/2006/content-types'})
            expected_from_ct = [o.get('PartName', '')[1:] for o in overrides if o.get('PartName', '').startswith('/word/')]
            expected.extend(expected_from_ct)
        
        # Find orphans
        for xml_file in xml_files:
            if xml_file not in expected and not xml_file.startswith('word/header') and not xml_file.startswith('word/footer'):
                size = self.loader.zip_ref.getinfo(xml_file).file_size
                if size > 0:  # Only report non-empty files
                    self.orphaned_xml.append({
                        'path': xml_file,
                        'size': size
                    })

    def _report_findings(self):
        """Report all deleted/orphaned content found."""
        total = len(self.orphaned_media) + len(self.orphaned_xml)
        
        if total == 0:
            log_success("No orphaned or deleted content found.")
            return
        
        log_warning(f"Found {total} orphaned items (deleted but not purged from archive)")
        
        if self.orphaned_media:
            log_danger(f"Found {len(self.orphaned_media)} orphaned media files:")
            total_size = sum(m['size'] for m in self.orphaned_media)
            print(f"  Total size: {total_size / 1024:.1f} KB")
            for media in self.orphaned_media[:10]:
                print(f"  [DELETED IMAGE] {media['name']} ({media['size'] / 1024:.1f} KB)")
            if len(self.orphaned_media) > 10:
                print(f"  ... and {len(self.orphaned_media) - 10} more deleted media files")
        
        if self.orphaned_xml:
            print(f"\n[ORPHANED XML PARTS]: {len(self.orphaned_xml)} zombie XML files")
            for xml in self.orphaned_xml:
                print(f"  • {xml['path']} ({xml['size']} bytes)")
