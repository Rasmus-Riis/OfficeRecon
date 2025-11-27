import zipfile
import os
from lxml import etree
from utils.helpers import log_danger

class DocLoader:
    def __init__(self, filepath):
        self.filepath = filepath
        self.zip_ref = None
        self.file_type = "unknown" 
        self._validate()

    def _validate(self):
        if not zipfile.is_zipfile(self.filepath):
            return

    def load(self):
        try:
            self.zip_ref = zipfile.ZipFile(self.filepath, 'r')
            self._detect_type()
            return True
        except Exception as e:
            return False

    def _detect_type(self):
        files = self.zip_ref.namelist()
        if 'word/document.xml' in files: self.file_type = 'docx'
        elif 'xl/workbook.xml' in files: self.file_type = 'xlsx'
        elif 'ppt/presentation.xml' in files: self.file_type = 'pptx'
        elif 'content.xml' in files and 'meta.xml' in files: self.file_type = 'odt'
        else: self.file_type = 'unknown'

    def get_xml_tree(self, xml_path):
        try:
            with self.zip_ref.open(xml_path) as f:
                return etree.parse(f)
        except: return None

    def get_bytes(self, path):
        """Helper to extract raw bytes (for images/thumbnails)."""
        try:
            return self.zip_ref.read(path)
        except: return None

    def close(self):
        if self.zip_ref:
            self.zip_ref.close()