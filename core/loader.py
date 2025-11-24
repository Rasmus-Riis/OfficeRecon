import zipfile
import os
from lxml import etree
from utils.helpers import log_danger

class DocLoader:
    def __init__(self, filepath):
        self.filepath = filepath
        self.zip_ref = None
        self._validate()

    def _validate(self):
        if not zipfile.is_zipfile(self.filepath):
            log_danger(f"File '{self.filepath}' is not a valid ZIP/OOXML container.")
            exit(1)

    def load(self):
        try:
            self.zip_ref = zipfile.ZipFile(self.filepath, 'r')
            return True
        except Exception as e:
            log_danger(f"Failed to open file: {e}")
            return False

    def get_xml_tree(self, xml_path):
        """Parses an XML file from inside the zip and returns an lxml object."""
        try:
            with self.zip_ref.open(xml_path) as f:
                return etree.parse(f)
        except KeyError:
            return None # File doesn't exist in this doc type
        except Exception as e:
            log_danger(f"Error parsing {xml_path}: {e}")
            return None

    def close(self):
        if self.zip_ref:
            self.zip_ref.close()