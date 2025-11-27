import subprocess
import shutil
import os
import sys
from utils.helpers import log_info, log_warning

class ExifToolScanner:
    def __init__(self, filepath):
        self.filepath = filepath
        self.exif_path = self._find_exiftool()

    def _find_exiftool(self):
        """
        Locates the ExifTool executable.
        Priority 1: Local directory (next to main script).
        Priority 2: System PATH.
        """
        # 1. Determine the application root directory
        if getattr(sys, 'frozen', False):
            # If running as a compiled exe (PyInstaller)
            base_dir = os.path.dirname(sys.executable)
        else:
            # If running as a script
            base_dir = os.path.dirname(os.path.abspath(sys.modules['__main__'].__file__))

        # 2. Check for local executable (Windows .exe or Unix binary)
        local_win = os.path.join(base_dir, "exiftool.exe")
        local_unix = os.path.join(base_dir, "exiftool")

        if os.path.exists(local_win):
            return local_win
        if os.path.exists(local_unix):
            return local_unix

        # 3. Fallback to System PATH
        return shutil.which("exiftool")

    def run(self):
        print("\n--- ExifTool Raw Metadata Analysis ---")
        
        if not self.exif_path:
            log_warning("ExifTool executable not found.")
            print("   [HOW TO FIX]:")
            print("   1. Download 'exiftool.exe' from https://exiftool.org/")
            print(f"   2. Place it in this folder: {os.path.dirname(os.path.abspath(sys.argv[0]))}")
            return

        try:
            # Prepare Windows-specific flags to hide the console window
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            # Run exiftool
            # -a: allow duplicate tags, -u: unknown tags, -g1: group by type
            result = subprocess.run(
                [self.exif_path, "-a", "-u", "-g1", self.filepath],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                startupinfo=startupinfo # <--- CORRECTED METHOD
            )
            
            if result.returncode == 0:
                print(result.stdout)
            else:
                print(f"   [Error running ExifTool]: {result.stderr}")

        except Exception as e:
            print(f"   [Execution Error]: {e}")