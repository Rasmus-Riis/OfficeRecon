import zipfile
import os
from lxml import etree
from utils.helpers import log_danger

class DocLoader:
    def __init__(self, filepath):
        self.filepath = filepath
        self.zip_ref = None
        self.file_type = "unknown" # 'docx' or 'odt'
        self._validate()

    def _validate(self):
        if not zipfile.is_zipfile(self.filepath):
            log_danger(f"File '{self.filepath}' is not a valid ZIP container.")
            # We don't exit hard here to allow GUI to handle error
            return

    def load(self):
        try:
            self.zip_ref = zipfile.ZipFile(self.filepath, 'r')
            self._detect_type()
            return True
        except Exception as e:
            log_danger(f"Failed to open file: {e}")
            return False

    def _detect_type(self):
        """Determines if this is a Word Doc or OpenOffice Doc."""
        files = self.zip_ref.namelist()
        if 'word/document.xml' in files:
            self.file_type = 'docx'
        elif 'content.xml' in files and 'meta.xml' in files:
            self.file_type = 'odt'
        else:
            self.file_type = 'unknown'

    def get_xml_tree(self, xml_path):
        """Parses an XML file from inside the zip and returns an lxml object."""
        try:
            with self.zip_ref.open(xml_path) as f:
                return etree.parse(f)
        except KeyError:
            return None 
        except Exception as e:
            return None

    def close(self):
        if self.zip_ref:
            self.zip_ref.close()