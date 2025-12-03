from utils.helpers import log_info, log_warning, log_success, log_danger

class ContentTypesAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.content_types = []
        self.overrides = []

    def run(self):
        print("\n--- Content Types Analysis ([Content_Types].xml) ---")
        self._extract_content_types()
        self._analyze_types()

    def _extract_content_types(self):
        """Extract all content types from [Content_Types].xml."""
        tree = self.loader.get_xml_tree('[Content_Types].xml')
        if not tree:
            log_danger("Could not read [Content_Types].xml")
            return

        # Extract default content types (by extension)
        defaults = tree.xpath('//ct:Default', namespaces={'ct': 'http://schemas.openxmlformats.org/package/2006/content-types'})
        
        for default in defaults:
            extension = default.get('Extension', '')
            content_type = default.get('ContentType', '')
            
            if extension and content_type:
                self.content_types.append({
                    'type': 'default',
                    'extension': extension,
                    'content_type': content_type
                })
        
        # Extract override content types (specific parts)
        overrides = tree.xpath('//ct:Override', namespaces={'ct': 'http://schemas.openxmlformats.org/package/2006/content-types'})
        
        for override in overrides:
            part_name = override.get('PartName', '')
            content_type = override.get('ContentType', '')
            
            if part_name and content_type:
                self.overrides.append({
                    'part': part_name,
                    'content_type': content_type
                })

    def _analyze_types(self):
        """Analyze content types for suspicious or unusual entries."""
        if not self.content_types and not self.overrides:
            log_danger("No content types found (corrupted document?)")
            return
        
        log_info(f"Content types: {len(self.content_types)} defaults, {len(self.overrides)} overrides")
        
        # Standard Office content types
        standard_types = {
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml',
            'application/vnd.openxmlformats-package.core-properties+xml',
            'application/vnd.openxmlformats-officedocument.extended-properties+xml',
            'application/vnd.openxmlformats-package.relationships+xml',
            'image/png',
            'image/jpeg',
            'image/gif'
        }
        
        # Check for unusual content types
        unusual = []
        suspicious = []
        
        for override in self.overrides:
            ct = override['content_type']
            part = override['part']
            
            # Check for suspicious types
            if any(keyword in ct.lower() for keyword in ['vba', 'macro', 'activex', 'ole', 'binary']):
                suspicious.append({
                    'part': part,
                    'type': ct,
                    'reason': 'Macro/OLE/ActiveX content'
                })
            
            # Check for non-standard types
            if ct not in standard_types and not any(std in ct for std in ['openxmlformats', 'image/', 'text/']):
                unusual.append({
                    'part': part,
                    'type': ct
                })
        
        if suspicious:
            log_danger(f"\n[SUSPICIOUS CONTENT TYPES]: {len(suspicious)}")
            for item in suspicious:
                print(f"  • {item['part']}")
                print(f"    Type: {item['type']}")
                print(f"    Reason: {item['reason']}")
        
        if unusual:
            log_warning(f"\n[UNUSUAL CONTENT TYPES]: {len(unusual)}")
            for item in unusual[:10]:
                print(f"  • {item['part']}")
                print(f"    Type: {item['type']}")
            if len(unusual) > 10:
                print(f"  ... and {len(unusual) - 10} more unusual types")
        
        # Check for embedded media
        media_types = [ct for ct in self.content_types if 'image' in ct['content_type'] or 'video' in ct['content_type'] or 'audio' in ct['content_type']]
        if media_types:
            log_info(f"\n[EMBEDDED MEDIA]: {len(media_types)} media type(s)")
            for media in media_types:
                print(f"  .{media['extension']}: {media['content_type']}")
        
        if not suspicious and not unusual:
            log_success("All content types are standard Office formats.")
