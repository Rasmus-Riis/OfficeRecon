"""
Enhanced Metadata Analyzer
Extracts detailed software versions, language, timezone, template information,
and system fingerprints.
"""

import re
import datetime
from utils.helpers import NS, log_info, log_warning, log_danger, log_success

class EnhancedMetadataAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        
    def run(self):
        print("\n--- Enhanced Metadata Analysis ---")
        self._extract_software_details()
        self._extract_language()
        self._extract_timezone_info()
        self._extract_template_info()
        self._extract_system_fingerprints()
        
    def _extract_software_details(self):
        """Extract detailed software version information."""
        print(f"\n{'[Software Details]':<25}")
        
        if self.loader.file_type in ['docx', 'xlsx', 'pptx']:
            tree = self.loader.get_xml_tree('docProps/app.xml')
            if tree:
                ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
                
                app = tree.xpath('//ep:Application', namespaces=ns)
                app_ver = tree.xpath('//ep:AppVersion', namespaces=ns)
                
                if app and app[0].text:
                    app_name = app[0].text
                    print(f"  Application: {app_name}")
                    
                    # Decode Office versions
                    if 'Microsoft Office Word' in app_name or 'Microsoft Excel' in app_name or 'Microsoft PowerPoint' in app_name:
                        if app_ver and app_ver[0].text:
                            version = app_ver[0].text
                            print(f"  Version: {version}")
                            
                            # Decode version to Office edition
                            major = version.split('.')[0] if '.' in version else version
                            office_editions = {
                                '12': 'Office 2007',
                                '14': 'Office 2010',
                                '15': 'Office 2013',
                                '16': 'Office 2016/2019/365'
                            }
                            if major in office_editions:
                                log_info(f"Identified: {office_editions[major]}")
                                
                # Check for LibreOffice/OpenOffice
                core_tree = self.loader.get_xml_tree('docProps/core.xml')
                if core_tree:
                    # Generator might be in core props too
                    generator_elems = core_tree.xpath('//*[local-name()="generator"]')
                    if generator_elems and generator_elems[0].text:
                        print(f"  Generator: {generator_elems[0].text}")
                        
        elif self.loader.file_type in ['odt', 'ods', 'odp']:
            tree = self.loader.get_xml_tree('meta.xml')
            if tree:
                ns = {'meta': 'urn:oasis:names:tc:opendocument:xmlns:meta:1.0'}
                
                generator = tree.xpath('//meta:generator', namespaces=ns)
                if generator and generator[0].text:
                    gen_text = generator[0].text
                    print(f"  Generator: {gen_text}")
                    
                    # Parse LibreOffice/OpenOffice version
                    if 'LibreOffice' in gen_text:
                        version_match = re.search(r'LibreOffice/(\d+\.\d+\.\d+\.\d+)', gen_text)
                        if version_match:
                            log_info(f"LibreOffice version: {version_match.group(1)}")
                    elif 'OpenOffice' in gen_text:
                        version_match = re.search(r'OpenOffice\.org/(\d+\.\d+)', gen_text)
                        if version_match:
                            log_info(f"OpenOffice version: {version_match.group(1)}")
    
    def _extract_language(self):
        """Extract document language information."""
        print(f"\n{'[Language Information]':<25}")
        
        languages = set()
        
        if self.loader.file_type == 'docx':
            tree = self.loader.get_xml_tree('word/document.xml')
            if tree:
                # Check language attributes in runs
                lang_elems = tree.xpath('//w:lang', namespaces=NS)
                for elem in lang_elems:
                    lang_val = elem.get(f"{{{NS['w']}}}val")
                    if lang_val:
                        languages.add(lang_val)
                    
                    # Also check bidi (bidirectional) and eastAsia languages
                    bidi_val = elem.get(f"{{{NS['w']}}}bidi")
                    if bidi_val:
                        languages.add(f"{bidi_val} (bidi)")
                    
                    east_asia = elem.get(f"{{{NS['w']}}}eastAsia")
                    if east_asia:
                        languages.add(f"{east_asia} (eastAsia)")
                        
        elif self.loader.file_type in ['xlsx', 'pptx']:
            # Check workbook/presentation properties
            tree = self.loader.get_xml_tree('docProps/core.xml')
            if tree:
                lang_elems = tree.xpath('//*[local-name()="language"]')
                for elem in lang_elems:
                    if elem.text:
                        languages.add(elem.text)
                        
        elif self.loader.file_type in ['odt', 'ods', 'odp']:
            tree = self.loader.get_xml_tree('meta.xml')
            if tree:
                ns = {'dc': 'http://purl.org/dc/elements/1.1/'}
                lang_elems = tree.xpath('//dc:language', namespaces=ns)
                for elem in lang_elems:
                    if elem.text:
                        languages.add(elem.text)
        
        if languages:
            lang_list = sorted(languages)
            print(f"  Languages detected: {', '.join(lang_list)}")
            
            # Flag unusual language combinations
            if len(lang_list) > 3:
                log_warning(f"Multiple languages detected ({len(lang_list)}) - possible document assembly")
        else:
            log_info("No explicit language information found (using system default)")
    
    def _extract_timezone_info(self):
        """Extract timezone information from timestamps."""
        print(f"\n{'[Timezone Information]':<25}")
        
        timezones = set()
        
        if self.loader.file_type in ['docx', 'xlsx', 'pptx']:
            tree = self.loader.get_xml_tree('docProps/core.xml')
            if tree:
                ns = {'dcterms': 'http://purl.org/dc/terms/'}
                
                for field in ['created', 'modified']:
                    elems = tree.xpath(f'//dcterms:{field}', namespaces=ns)
                    if elems and elems[0].text:
                        timestamp_str = elems[0].text
                        # Check for timezone info
                        if '+' in timestamp_str or timestamp_str.endswith('Z'):
                            if timestamp_str.endswith('Z'):
                                timezones.add('UTC (Z)')
                            else:
                                tz_match = re.search(r'([+-]\d{2}:\d{2})$', timestamp_str)
                                if tz_match:
                                    timezones.add(tz_match.group(1))
                        else:
                            timezones.add('No timezone (local time)')
                            
        elif self.loader.file_type in ['odt', 'ods', 'odp']:
            tree = self.loader.get_xml_tree('meta.xml')
            if tree:
                ns = {'meta': 'urn:oasis:names:tc:opendocument:xmlns:meta:1.0',
                      'dc': 'http://purl.org/dc/elements/1.1/'}
                      
                for xpath in ['//meta:creation-date', '//dc:date']:
                    elems = tree.xpath(xpath, namespaces=ns)
                    if elems and elems[0].text:
                        timestamp_str = elems[0].text
                        if '+' in timestamp_str or timestamp_str.endswith('Z'):
                            if timestamp_str.endswith('Z'):
                                timezones.add('UTC (Z)')
                            else:
                                tz_match = re.search(r'([+-]\d{2}:\d{2})$', timestamp_str)
                                if tz_match:
                                    timezones.add(tz_match.group(1))
                        else:
                            timezones.add('No timezone (local time)')
        
        if timezones:
            print(f"  Timezones found: {', '.join(sorted(timezones))}")
            
            # Check for timezone inconsistencies
            if len(timezones) > 1 and 'No timezone (local time)' not in timezones:
                log_warning("Multiple timezones detected - document edited in different locations")
        else:
            log_info("No timezone information available")
    
    def _extract_template_info(self):
        """Extract template information."""
        print(f"\n{'[Template Information]':<25}")
        
        if self.loader.file_type == 'docx':
            # Check settings.xml for attached template
            tree = self.loader.get_xml_tree('word/settings.xml')
            if tree:
                template_elems = tree.xpath('//w:attachedTemplate', namespaces=NS)
                if template_elems:
                    template_rel = template_elems[0].get(f"{{{NS['r']}}}id")
                    if template_rel:
                        # Get the actual template path from relationships
                        rels_tree = self.loader.get_xml_tree('word/_rels/settings.xml.rels')
                        if rels_tree:
                            rel = rels_tree.xpath(f'//rel:Relationship[@Id="{template_rel}"]', namespaces=NS)
                            if rel:
                                template_path = rel[0].get('Target', '')
                                if template_path:
                                    log_warning(f"Attached template: {template_path}")
                                    
                                    # Check if it's a custom corporate template
                                    if '\\\\' in template_path:  # UNC path
                                        log_danger("Template on network share - reveals internal network structure")
                                    elif any(x in template_path.lower() for x in ['company', 'corporate', 'custom']):
                                        log_info("Custom corporate template detected")
                                    
            # Check for template metadata in app.xml
            tree = self.loader.get_xml_tree('docProps/app.xml')
            if tree:
                ns = {'ep': 'http://schemas.openxmlformats.org/officeDocument/2006/extended-properties'}
                template = tree.xpath('//ep:Template', namespaces=ns)
                if template and template[0].text:
                    print(f"  Template name: {template[0].text}")
                else:
                    log_success("No template information found")
        else:
            log_info(f"Template analysis not applicable to {self.loader.file_type.upper()}")
    
    def _extract_system_fingerprints(self):
        """Extract system fingerprints (computer names, usernames from paths)."""
        print(f"\n{'[System Fingerprints]':<25}")
        
        computer_names = set()
        usernames = set()
        paths = set()
        
        # Check all XML files for embedded paths
        for xml_file in self.loader.zip_ref.namelist():
            if xml_file.endswith('.xml'):
                tree = self.loader.get_xml_tree(xml_file)
                if tree:
                    # Convert to string to search for paths
                    import xml.etree.ElementTree as ET
                    # Handle both Element and ElementTree objects
                    root = tree.getroot() if hasattr(tree, 'getroot') else tree
                    xml_str = ET.tostring(root, encoding='unicode', method='text')
                    
                    # Find Windows paths with usernames
                    # Pattern: C:\Users\username\...
                    user_paths = re.findall(r'[Cc]:\\[Uu]sers\\([^\\]+)\\', xml_str)
                    usernames.update(user_paths)
                    
                    # Find computer names from UNC paths
                    # Pattern: \\computername\share
                    comp_names = re.findall(r'\\\\([^\\]+)\\', xml_str)
                    computer_names.update(comp_names)
                    
                    # Collect interesting paths
                    all_paths = re.findall(r'[A-Z]:\\(?:[^\\<>"|\r\n]+\\)*[^\\<>"|\r\n]+', xml_str, re.IGNORECASE)
                    paths.update(all_paths[:10])  # Limit to first 10 unique paths
        
        if usernames:
            log_warning(f"Found {len(usernames)} username(s) in file paths:")
            for username in sorted(usernames)[:5]:
                print(f"  → {username}")
                
        if computer_names:
            log_warning(f"Found {len(computer_names)} computer name(s):")
            for comp in sorted(computer_names)[:5]:
                print(f"  → {comp}")
                
        if paths:
            log_info("Sample paths found in document:")
            for path in list(paths)[:3]:
                print(f"  → {path}")
                
        if not (usernames or computer_names or paths):
            log_success("No system fingerprints detected")
