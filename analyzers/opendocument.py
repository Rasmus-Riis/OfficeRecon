"""
OpenDocument Analyzer - Forensic Analysis for ODT, ODS, ODP Files
Supports LibreOffice and OpenOffice formats.
Extracts metadata, tracked changes, comments, version history, and hidden content.
"""
from utils.helpers import log_info, log_warning, log_success, log_danger
from lxml import etree
import zipfile


class OpenDocumentAnalyzer:
    """Unified analyzer for ODT (text), ODS (spreadsheet), and ODP (presentation)."""
    
    # OpenDocument namespaces
    OD_NS = {
        'office': 'urn:oasis:names:tc:opendocument:xmlns:office:1.0',
        'meta': 'urn:oasis:names:tc:opendocument:xmlns:meta:1.0',
        'dc': 'http://purl.org/dc/elements/1.1/',
        'text': 'urn:oasis:names:tc:opendocument:xmlns:text:1.0',
        'table': 'urn:oasis:names:tc:opendocument:xmlns:table:1.0',
        'draw': 'urn:oasis:names:tc:opendocument:xmlns:drawing:1.0',
        'presentation': 'urn:oasis:names:tc:opendocument:xmlns:presentation:1.0',
        'style': 'urn:oasis:names:tc:opendocument:xmlns:style:1.0',
        'number': 'urn:oasis:names:tc:opendocument:xmlns:datastyle:1.0',
        'config': 'urn:oasis:names:tc:opendocument:xmlns:config:1.0',
        'manifest': 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0',
    }
    
    def __init__(self, loader):
        self.loader = loader
        self.file_type = loader.file_type
        
    def run(self):
        print(f"\n--- OpenDocument Forensics ({self.file_type.upper()}) ---")
        
        self._analyze_metadata()
        self._scan_tracked_changes()
        self._scan_comments()
        self._scan_version_history()
        self._scan_hidden_content()
        self._scan_macros()
        self._scan_embedded_objects()
        self._scan_custom_properties()
        self._scan_protection()
        
        # Format-specific analysis
        if self.file_type == 'odt':
            self._analyze_odt_specific()
        elif self.file_type == 'ods':
            self._analyze_ods_specific()
        elif self.file_type == 'odp':
            self._analyze_odp_specific()

    def _analyze_metadata(self):
        """Extract comprehensive metadata from meta.xml."""
        print(f"\n{'[OpenDocument Metadata]':<25}")
        
        tree = self.loader.get_xml_tree('meta.xml')
        if not tree:
            log_warning("meta.xml not found")
            return
        
        ns = self.OD_NS
        
        # Core metadata fields
        fields = {
            'Generator': '//meta:generator',
            'Title': '//dc:title',
            'Description': '//dc:description',
            'Subject': '//dc:subject',
            'Creator': '//dc:creator',
            'Created': '//meta:creation-date',
            'Modified By': '//dc:creator',
            'Modified': '//dc:date',
            'Language': '//dc:language',
            'Keywords': '//meta:keyword',
            'Editing Cycles': '//meta:editing-cycles',
            'Edit Time': '//meta:editing-duration',
            'Initial Creator': '//meta:initial-creator',
            'Print Date': '//meta:print-date',
            'Printed By': '//meta:printed-by',
        }
        
        for label, xpath in fields.items():
            elem = tree.xpath(xpath, namespaces=ns)
            if elem and elem[0].text:
                value = elem[0].text
                # Format duration nicely
                if label == 'Edit Time' and 'PT' in value:
                    value = self._format_duration(value)
                print(f"  {label:<20}: {value}")
        
        # Document statistics
        stats = tree.xpath('//meta:document-statistic', namespaces=ns)
        if stats:
            stat = stats[0]
            print(f"\n{'[Document Statistics]':<25}")
            for attr in stat.attrib:
                attr_name = attr.split('}')[-1]  # Remove namespace
                value = stat.get(attr)
                print(f"  {attr_name:<20}: {value}")

    def _format_duration(self, duration):
        """Convert ISO 8601 duration (PT1H30M) to readable format."""
        import re
        hours = re.search(r'(\d+)H', duration)
        minutes = re.search(r'(\d+)M', duration)
        seconds = re.search(r'(\d+)S', duration)
        
        parts = []
        if hours:
            parts.append(f"{hours.group(1)}h")
        if minutes:
            parts.append(f"{minutes.group(1)}m")
        if seconds:
            parts.append(f"{seconds.group(1)}s")
        
        return " ".join(parts) if parts else duration

    def _scan_tracked_changes(self):
        """Detect tracked changes/revisions in the document."""
        print(f"\n{'[Tracked Changes]':<25}")
        
        tree = self.loader.get_xml_tree('content.xml')
        if not tree:
            return
        
        ns = self.OD_NS
        
        # Look for change tracking elements
        tracked_changes = tree.xpath('//text:tracked-changes', namespaces=ns)
        
        if tracked_changes:
            changes = tree.xpath('//text:changed-region', namespaces=ns)
            
            log_warning(f"TRACKED CHANGES DETECTED: {len(changes)} change(s)")
            
            for i, change in enumerate(changes[:10], 1):
                change_id = change.get(f"{{{ns['text']}}}id", 'unknown')
                
                # Check for insertion, deletion, or format change
                insertion = change.xpath('.//text:insertion', namespaces=ns)
                deletion = change.xpath('.//text:deletion', namespaces=ns)
                format_change = change.xpath('.//text:format-change', namespaces=ns)
                
                if insertion:
                    author = insertion[0].xpath('./office:change-info/dc:creator', namespaces=ns)
                    date = insertion[0].xpath('./office:change-info/dc:date', namespaces=ns)
                    author_str = author[0].text if author and author[0].text else "Unknown"
                    date_str = date[0].text if date and date[0].text else "N/A"
                    print(f"  [{i}] INSERTION by {author_str} on {date_str}")
                
                elif deletion:
                    author = deletion[0].xpath('./office:change-info/dc:creator', namespaces=ns)
                    date = deletion[0].xpath('./office:change-info/dc:date', namespaces=ns)
                    author_str = author[0].text if author and author[0].text else "Unknown"
                    date_str = date[0].text if date and date[0].text else "N/A"
                    
                    # Try to extract deleted text
                    deleted_text = deletion[0].xpath('.//text:p//text()', namespaces=ns)
                    text_preview = "".join(deleted_text)[:60] if deleted_text else "[binary/complex]"
                    
                    log_danger(f"  [{i}] DELETION by {author_str} on {date_str}: \"{text_preview}\"")
                
                elif format_change:
                    print(f"  [{i}] FORMAT CHANGE")
            
            if len(changes) > 10:
                print(f"  ... and {len(changes) - 10} more changes")
        else:
            log_success("No tracked changes found.")

    def _scan_comments(self):
        """Extract comments and annotations."""
        print(f"\n{'[Comments & Annotations]':<25}")
        
        tree = self.loader.get_xml_tree('content.xml')
        if not tree:
            return
        
        ns = self.OD_NS
        
        # ODT/ODS comments
        comments = tree.xpath('//office:annotation', namespaces=ns)
        
        if comments:
            log_warning(f"Found {len(comments)} comment(s)")
            
            authors = set()
            for i, comment in enumerate(comments[:10], 1):
                author = comment.xpath('./dc:creator', namespaces=ns)
                date = comment.xpath('./dc:date', namespaces=ns)
                text_nodes = comment.xpath('.//text:p//text()', namespaces=ns)
                
                author_str = author[0].text if author and author[0].text else "Unknown"
                date_str = date[0].text if date and date[0].text else "N/A"
                text = "".join(text_nodes)[:80] if text_nodes else ""
                
                authors.add(author_str)
                
                print(f"  [{i}] {author_str} ({date_str}): \"{text}\"")
            
            if len(comments) > 10:
                print(f"  ... and {len(comments) - 10} more comments")
            
            print(f"\n  Comment Authors: {', '.join(authors)}")
        else:
            log_success("No comments found.")

    def _scan_version_history(self):
        """Check for version history in Versions/ directory."""
        print(f"\n{'[Version History]':<25}")
        
        versions = self.loader.list_files(prefix='Versions/')
        
        if versions:
            log_warning(f"VERSION HISTORY DETECTED: {len(versions)} version(s)")
            for version in versions[:5]:
                print(f"  -> {version}")
            if len(versions) > 5:
                print(f"  -> ... and {len(versions) - 5} more")
        else:
            log_success("No version history found.")

    def _scan_hidden_content(self):
        """Scan for hidden text, sections, sheets, or slides."""
        print(f"\n{'[Hidden Content]':<25}")
        
        tree = self.loader.get_xml_tree('content.xml')
        if not tree:
            return
        
        ns = self.OD_NS
        hidden_found = False
        
        if self.file_type == 'odt':
            # Hidden text
            hidden_text = tree.xpath('//text:hidden-text', namespaces=ns)
            if hidden_text:
                log_warning(f"Hidden text elements: {len(hidden_text)}")
                hidden_found = True
            
            # Hidden paragraphs
            hidden_paras = tree.xpath('//text:hidden-paragraph', namespaces=ns)
            if hidden_paras:
                log_warning(f"Hidden paragraphs: {len(hidden_paras)}")
                hidden_found = True
        
        elif self.file_type == 'ods':
            # Hidden sheets
            sheets = tree.xpath('//table:table', namespaces=ns)
            for sheet in sheets:
                visibility = sheet.get(f"{{{ns['table']}}}display", 'true')
                if visibility == 'false':
                    name = sheet.get(f"{{{ns['table']}}}name", 'unknown')
                    log_warning(f"Hidden sheet: {name}")
                    hidden_found = True
            
            # Hidden rows/columns
            hidden_rows = tree.xpath('//table:table-row[@table:visibility="collapse"]', namespaces=ns)
            hidden_cols = tree.xpath('//table:table-column[@table:visibility="collapse"]', namespaces=ns)
            
            if hidden_rows:
                log_warning(f"Hidden rows detected: {len(hidden_rows)}")
                hidden_found = True
            if hidden_cols:
                log_warning(f"Hidden columns detected: {len(hidden_cols)}")
                hidden_found = True
        
        elif self.file_type == 'odp':
            # Hidden slides
            slides = tree.xpath('//draw:page', namespaces=ns)
            for slide in slides:
                visibility = slide.get(f"{{{ns['presentation']}}}visibility", 'visible')
                if visibility == 'hidden':
                    name = slide.get(f"{{{ns['draw']}}}name", 'unknown')
                    log_warning(f"Hidden slide: {name}")
                    hidden_found = True
        
        if not hidden_found:
            log_success("No hidden content detected.")

    def _scan_macros(self):
        """Detect macros and scripts."""
        print(f"\n{'[Macro Detection]':<25}")
        
        # Check for Basic macros
        if self.loader.file_exists('Basic/'):
            basic_files = self.loader.list_files(prefix='Basic/')
            if basic_files:
                log_danger(f"MACROS DETECTED: {len(basic_files)} Basic macro file(s)")
                for macro in basic_files[:5]:
                    print(f"  -> {macro}")
                if len(basic_files) > 5:
                    print(f"  -> ... and {len(basic_files) - 5} more")
            else:
                log_success("No macros found.")
        else:
            log_success("No macros found.")
        
        # Check for scripts in manifest
        manifest = self.loader.get_xml_tree('META-INF/manifest.xml')
        if manifest:
            ns = self.OD_NS
            scripts = manifest.xpath('//manifest:file-entry[contains(@manifest:media-type, "script")]', namespaces=ns)
            if scripts:
                log_warning(f"Script entries in manifest: {len(scripts)}")

    def _scan_embedded_objects(self):
        """Detect embedded objects."""
        print(f"\n{'[Embedded Objects]':<25}")
        
        objects = self.loader.list_files(prefix='Object')
        
        if objects:
            log_warning(f"Embedded objects detected: {len(objects)}")
            
            # Group by object directory
            object_dirs = set()
            for obj in objects:
                if '/' in obj:
                    obj_dir = obj.split('/')[0] + '/' + obj.split('/')[1] if obj.count('/') > 1 else obj.split('/')[0]
                    object_dirs.add(obj_dir)
            
            for obj_dir in list(object_dirs)[:5]:
                print(f"  -> {obj_dir}")
            if len(object_dirs) > 5:
                print(f"  -> ... and {len(object_dirs) - 5} more")
        else:
            log_success("No embedded objects detected.")

    def _scan_custom_properties(self):
        """Extract custom metadata properties."""
        tree = self.loader.get_xml_tree('meta.xml')
        if not tree:
            return
        
        ns = self.OD_NS
        
        # User-defined metadata
        user_defined = tree.xpath('//meta:user-defined', namespaces=ns)
        
        if user_defined:
            print(f"\n{'[Custom Properties]':<25}")
            for prop in user_defined[:10]:
                name = prop.get(f"{{{ns['meta']}}}name", 'Unknown')
                value = prop.text or 'N/A'
                print(f"  {name:<20}: {value}")
            
            if len(user_defined) > 10:
                print(f"  ... and {len(user_defined) - 10} more properties")

    def _scan_protection(self):
        """Check for document protection."""
        print(f"\n{'[Protection Status]':<25}")
        
        tree = self.loader.get_xml_tree('content.xml')
        if not tree:
            return
        
        ns = self.OD_NS
        
        # Check for protected sections
        protected_sections = tree.xpath('//text:section[@text:protected="true"]', namespaces=ns)
        if protected_sections:
            log_warning(f"Protected sections: {len(protected_sections)}")
            for section in protected_sections[:5]:
                name = section.get(f"{{{ns['text']}}}name", 'unknown')
                print(f"  -> {name}")
        
        # Check settings.xml for protection
        settings = self.loader.get_xml_tree('settings.xml')
        if settings:
            # Protection settings vary by implementation
            protection = settings.xpath('//*[contains(local-name(), "protect") or contains(local-name(), "Protected")]')
            if protection:
                log_warning("Protection settings found in settings.xml")
        
        if not protected_sections:
            log_success("No document protection detected.")

    def _analyze_odt_specific(self):
        """ODT-specific forensic analysis."""
        print(f"\n{'[ODT Specific Analysis]':<25}")
        
        tree = self.loader.get_xml_tree('content.xml')
        if not tree:
            return
        
        ns = self.OD_NS
        
        # Count document elements
        paragraphs = tree.xpath('//text:p', namespaces=ns)
        headings = tree.xpath('//text:h', namespaces=ns)
        lists = tree.xpath('//text:list', namespaces=ns)
        tables = tree.xpath('//table:table', namespaces=ns)
        images = tree.xpath('//draw:frame[draw:image]', namespaces=ns)
        
        print(f"  Paragraphs: {len(paragraphs)}")
        print(f"  Headings: {len(headings)}")
        print(f"  Lists: {len(lists)}")
        print(f"  Tables: {len(tables)}")
        print(f"  Images: {len(images)}")
        
        # Check for fields (can contain dynamic/hidden content)
        fields = tree.xpath('//text:*[contains(local-name(), "field")]', namespaces=ns)
        if fields:
            log_info(f"Document fields: {len(fields)}")

    def _analyze_ods_specific(self):
        """ODS-specific forensic analysis."""
        print(f"\n{'[ODS Specific Analysis]':<25}")
        
        tree = self.loader.get_xml_tree('content.xml')
        if not tree:
            return
        
        ns = self.OD_NS
        
        # Count sheets and cells
        sheets = tree.xpath('//table:table', namespaces=ns)
        print(f"  Total Sheets: {len(sheets)}")
        
        for sheet in sheets[:5]:
            name = sheet.get(f"{{{ns['table']}}}name", 'unknown')
            rows = sheet.xpath('.//table:table-row', namespaces=ns)
            print(f"    -> {name}: {len(rows)} rows")
        
        # Check for formulas
        formulas = tree.xpath('//table:table-cell[@table:formula]', namespaces=ns)
        if formulas:
            log_info(f"Cells with formulas: {len(formulas)}")
            
            # Check for suspicious formulas
            suspicious = []
            for cell in formulas[:100]:
                formula = cell.get(f"{{{ns['table']}}}formula", '')
                if any(keyword in formula.upper() for keyword in ['HYPERLINK', 'WEBSERVICE', 'INDIRECT']):
                    suspicious.append(formula[:80])
            
            if suspicious:
                log_danger(f"SUSPICIOUS FORMULAS: {len(suspicious)}")
                for f in suspicious[:3]:
                    print(f"    -> {f}")

    def _analyze_odp_specific(self):
        """ODP-specific forensic analysis."""
        print(f"\n{'[ODP Specific Analysis]':<25}")
        
        tree = self.loader.get_xml_tree('content.xml')
        if not tree:
            return
        
        ns = self.OD_NS
        
        # Count slides
        slides = tree.xpath('//draw:page', namespaces=ns)
        print(f"  Total Slides: {len(slides)}")
        
        # Check for slide notes
        notes_count = 0
        for slide in slides:
            notes = slide.xpath('.//presentation:notes', namespaces=ns)
            if notes:
                notes_count += 1
        
        if notes_count > 0:
            log_warning(f"Slides with notes: {notes_count}")
        
        # Check for animations
        animations = tree.xpath('//anim:*', namespaces={'anim': 'urn:oasis:names:tc:opendocument:xmlns:animation:1.0'})
        if animations:
            log_info(f"Animation elements: {len(animations)}")
