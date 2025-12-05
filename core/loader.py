import zipfile
import os
import signal
import sys
from lxml import etree
from utils.helpers import log_danger
import logging

# Setup simple file logging for loader
logging.basicConfig(
    filename=os.path.join(os.path.expanduser('~'), 'OfficeRecon_loader.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Operation timed out")

class DocLoader:
    def __init__(self, filepath):
        self.filepath = filepath
        self.zip_ref = None
        self.file_type = "unknown" 
        self._validate()

    def _is_cloud_placeholder(self):
        """Detect if file is a cloud placeholder (OneDrive, Dropbox, etc.)."""
        try:
            # Skip check for temp files (from ZIP extraction)
            if '\\Temp\\' in self.filepath or '/tmp/' in self.filepath:
                return False
            
            # Check file existence first
            if not os.path.exists(self.filepath):
                return False
            
            # Check file size - cloud placeholders are often 0 bytes or very small
            size = os.path.getsize(self.filepath)
            if size == 0:
                return True
            
            # On Windows, check FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
            if sys.platform == 'win32':
                import ctypes
                FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000
                attrs = ctypes.windll.kernel32.GetFileAttributesW(self.filepath)
                if attrs != -1 and (attrs & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS):
                    return True
            
            # Check for common cloud placeholder indicators
            # These files often have special attributes or are very small
            if size < 100:  # Suspiciously small for an Office document
                return True
                
        except Exception as e:
            # Log to file instead of console
            logging.warning(f"Error checking cloud status for {self.filepath}: {e}")
        return False

    def _validate(self):
        # Check if it's a cloud placeholder BEFORE attempting to open
        if self._is_cloud_placeholder():
            # Silently skip cloud placeholders (no need to spam console)
            return
            
        try:
            # Use timeout for is_zipfile check on Windows
            if sys.platform != 'win32':
                # Unix-like systems support SIGALRM
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(3)  # 3 second timeout
            
            if not zipfile.is_zipfile(self.filepath):
                if sys.platform != 'win32':
                    signal.alarm(0)  # Cancel alarm
                return
                
            if sys.platform != 'win32':
                signal.alarm(0)  # Cancel alarm
        except TimeoutError:
            log_danger(f"Timeout checking if file is zip: {self.filepath}")
            return
        except:
            return

    def load(self):
        try:
            # Additional cloud check before opening
            if self._is_cloud_placeholder():
                # Silently skip cloud placeholders (no need to spam console)
                return False
            
            # Try to open with timeout protection
            if sys.platform != 'win32':
                signal.signal(signal.SIGALRM, timeout_handler)
                signal.alarm(5)  # 5 second timeout
            
            self.zip_ref = zipfile.ZipFile(self.filepath, 'r')
            self._detect_type()
            
            if sys.platform != 'win32':
                signal.alarm(0)  # Cancel alarm
            return True
        except TimeoutError:
            log_danger(f"Timeout loading file: {self.filepath}")
            return False
        except Exception as e:
            if sys.platform != 'win32':
                signal.alarm(0)  # Cancel alarm
            return False

    def _detect_type(self):
        """Enhanced format detection for DOCX, XLSX, PPTX, ODT, ODS, ODP."""
        files = self.zip_ref.namelist()
        
        # OpenXML formats (Microsoft Office)
        if 'word/document.xml' in files: 
            self.file_type = 'docx'
        elif 'xl/workbook.xml' in files: 
            self.file_type = 'xlsx'
        elif 'ppt/presentation.xml' in files: 
            self.file_type = 'pptx'
        # OpenDocument formats (LibreOffice/OpenOffice)
        elif 'content.xml' in files and 'meta.xml' in files:
            # Check mimetype to distinguish between ODT, ODS, ODP
            try:
                mimetype = self.zip_ref.read('mimetype').decode('utf-8').strip()
                if 'text' in mimetype:
                    self.file_type = 'odt'
                elif 'spreadsheet' in mimetype:
                    self.file_type = 'ods'
                elif 'presentation' in mimetype:
                    self.file_type = 'odp'
                else:
                    self.file_type = 'odt'  # default to ODT
            except:
                self.file_type = 'odt'  # fallback
        else: 
            self.file_type = 'unknown'

    def get_xml_tree(self, xml_path):
        """Parse an XML file from the archive."""
        try:
            with self.zip_ref.open(xml_path) as f:
                return etree.parse(f)
        except: 
            return None

    def get_bytes(self, path):
        """Helper to extract raw bytes (for images/thumbnails)."""
        try:
            return self.zip_ref.read(path)
        except: 
            return None
    
    def file_exists(self, path):
        """Check if a file exists in the archive."""
        return path in self.zip_ref.namelist()
    
    def list_files(self, prefix='', suffix=''):
        """List files in the archive with optional prefix/suffix filter."""
        files = self.zip_ref.namelist()
        if prefix and suffix:
            return [f for f in files if f.startswith(prefix) and f.endswith(suffix)]
        elif prefix:
            return [f for f in files if f.startswith(prefix)]
        elif suffix:
            return [f for f in files if f.endswith(suffix)]
        return files

    def close(self):
        if self.zip_ref:
            self.zip_ref.close()