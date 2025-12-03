from utils.helpers import NS, log_info, log_warning, log_success

class FootnoteAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.footnotes = []
        self.endnotes = []

    def run(self):
        print("\n--- Footnote & Endnote Analysis ---")
        self._extract_footnotes()
        self._extract_endnotes()
        self._report_findings()

    def _extract_footnotes(self):
        """Extract all footnotes with metadata."""
        tree = self.loader.get_xml_tree('word/footnotes.xml')
        if not tree:
            return

        notes = tree.xpath('//w:footnote', namespaces=NS)
        
        for note in notes:
            note_id = note.get(f"{{{NS['w']}}}id", '')
            note_type = note.get(f"{{{NS['w']}}}type", 'normal')
            
            # Skip separator and continuation separator
            if note_type in ['separator', 'continuationSeparator']:
                continue
            
            # Extract text content
            text_nodes = note.xpath('.//w:t', namespaces=NS)
            text = ''.join([t.text or '' for t in text_nodes])
            
            if text.strip():
                self.footnotes.append({
                    'id': note_id,
                    'type': note_type,
                    'text': text.strip()
                })

    def _extract_endnotes(self):
        """Extract all endnotes with metadata."""
        tree = self.loader.get_xml_tree('word/endnotes.xml')
        if not tree:
            return

        notes = tree.xpath('//w:endnote', namespaces=NS)
        
        for note in notes:
            note_id = note.get(f"{{{NS['w']}}}id", '')
            note_type = note.get(f"{{{NS['w']}}}type", 'normal')
            
            # Skip separator and continuation separator
            if note_type in ['separator', 'continuationSeparator']:
                continue
            
            # Extract text content
            text_nodes = note.xpath('.//w:t', namespaces=NS)
            text = ''.join([t.text or '' for t in text_nodes])
            
            if text.strip():
                self.endnotes.append({
                    'id': note_id,
                    'type': note_type,
                    'text': text.strip()
                })

    def _report_findings(self):
        """Report all footnotes and endnotes found."""
        total = len(self.footnotes) + len(self.endnotes)
        
        if total == 0:
            log_success("No footnotes or endnotes found.")
            return
        
        log_info(f"Found {total} note(s): {len(self.footnotes)} footnote(s), {len(self.endnotes)} endnote(s)")
        
        if self.footnotes:
            print("\n[FOOTNOTES]:")
            for note in self.footnotes[:5]:
                preview = note['text'][:100] + "..." if len(note['text']) > 100 else note['text']
                print(f"  [{note['id']}] {preview}")
            if len(self.footnotes) > 5:
                print(f"  ... and {len(self.footnotes) - 5} more footnotes")
        
        if self.endnotes:
            print("\n[ENDNOTES]:")
            for note in self.endnotes[:5]:
                preview = note['text'][:100] + "..." if len(note['text']) > 100 else note['text']
                print(f"  [{note['id']}] {preview}")
            if len(self.endnotes) > 5:
                print(f"  ... and {len(self.endnotes) - 5} more endnotes")
