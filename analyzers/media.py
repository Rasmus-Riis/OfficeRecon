import io
from utils.helpers import log_info, log_warning, log_danger
try:
    from PIL import Image, ExifTags
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

class MediaAnalyzer:
    def __init__(self, loader):
        self.loader = loader

    def run(self):
        print("\n--- Embedded Media & EXIF Analysis ---")
        if not PIL_AVAILABLE:
            log_warning("Pillow not installed. EXIF disabled.")
        self._scan_media_content()

    def _scan_media_content(self):
        # DOCX uses 'word/media/', ODT uses 'Pictures/'
        all_files = self.loader.zip_ref.namelist()
        media_files = [f for f in all_files if f.startswith('word/media/') or f.startswith('Pictures/')]
        
        if not media_files:
            print("   -> No embedded images found.")
            return

        log_info(f"Found {len(media_files)} embedded media files. Scanning...")
        
        count = 0
        for mf in media_files:
            size_kb = self.loader.zip_ref.getinfo(mf).file_size / 1024
            ext = mf.split('.')[-1].lower()
            
            if size_kb > 5000:
                log_warning(f"Large Media: {mf} ({size_kb:.2f} KB)")
            
            if PIL_AVAILABLE and ext in ['jpg', 'jpeg', 'tiff', 'png']:
                if self._extract_exif(mf): count += 1

        if count == 0 and PIL_AVAILABLE:
            print("   -> Scanned images. No hidden EXIF data found.")

    def _extract_exif(self, filename):
        try:
            img_data = self.loader.zip_ref.read(filename)
            img = Image.open(io.BytesIO(img_data))
            exif = img._getexif()
            if not exif: return False

            tags_found = []
            for tag_id, val in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)
                if tag in ["GPSInfo", "Model", "Software", "DateTimeOriginal", "Artist", "XPAuthor"]:
                    tags_found.append(f"{tag}: {val}")

            if tags_found:
                log_warning(f"Metadata in {filename.split('/')[-1]}:")
                for t in tags_found: print(f"   -> {t}")
                return True
        except: pass
        return False