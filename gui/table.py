import customtkinter as ctk
from tkinter import Canvas, Scrollbar
import tkinter.font as tkfont
import math

class ForensicTable(ctk.CTkFrame):
    def __init__(self, master, columns, on_double_click, on_right_click):
        super().__init__(master, fg_color="transparent")
        
        self.columns = columns
        self.on_double_click_callback = on_double_click
        self.on_right_click_callback = on_right_click
        
        self.all_data = []    
        self.table_data = []  
        self.row_map = {}
        self.index_map = {}
        
        self.total_width = sum(c["width"] for c in columns)
        self.current_sort = {"col": None, "reverse": False}
        self.font_main = tkfont.Font(family="Segoe UI", size=10)
        self.line_height = 20 # Slightly taller for better readability
        self.selected_index = None

        # Layout
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._setup_ui()

    def _setup_ui(self):
        self.h_scroll = Scrollbar(self, orient="horizontal")
        self.v_scroll = Scrollbar(self, orient="vertical")

        self.header_canvas = Canvas(self, height=40, bg="#2b2b2b", bd=0, highlightthickness=0, 
                                    xscrollcommand=self.h_scroll.set)
        self.header_canvas.grid(row=0, column=0, sticky="ew")

        self.body_canvas = Canvas(self, bg="#1e1e1e", bd=0, highlightthickness=0,
                                  xscrollcommand=self.h_scroll.set, yscrollcommand=self.v_scroll.set)
        self.body_canvas.grid(row=1, column=0, sticky="nsew")

        self.h_scroll.config(command=self._multiple_xview)
        self.v_scroll.config(command=self.body_canvas.yview)
        self.h_scroll.grid(row=2, column=0, sticky="ew")
        self.v_scroll.grid(row=1, column=1, sticky="ns")

        self.header_frame = ctk.CTkFrame(self.header_canvas, fg_color="#2b2b2b", width=self.total_width, height=40)
        self.header_canvas.create_window((0, 0), window=self.header_frame, anchor="nw")
        
        self._draw_header_buttons()
        
        self.body_canvas.bind("<Button-1>", self._on_click)
        self.body_canvas.bind("<Double-Button-1>", self._on_double_click)
        self.body_canvas.bind("<Button-3>", self._on_right_click)
        self.body_canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.body_canvas.bind("<Up>", self._on_arrow_up)
        self.body_canvas.bind("<Down>", self._on_arrow_down)

    def _multiple_xview(self, *args):
        self.header_canvas.xview(*args)
        self.body_canvas.xview(*args)

    def _on_mousewheel(self, event):
        self.body_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def _draw_header_buttons(self):
        current_x = 0
        for col in self.columns:
            f = ctk.CTkFrame(self.header_frame, width=col["width"], height=40, fg_color="transparent")
            f.pack_propagate(False)
            f.place(x=current_x, y=0)
            btn = ctk.CTkButton(f, text=col["label"], fg_color="transparent", text_color="white",
                                font=("Segoe UI", 11, "bold"), anchor="w",
                                command=lambda c=col["key"]: self.sort_data(c))
            btn.pack(fill="both", expand=True, padx=5)
            current_x += col["width"]
        self.header_frame.configure(width=self.total_width)
        self.header_canvas.configure(scrollregion=(0, 0, self.total_width, 40))

    # --- DATA ---
    def add_row(self, row_data):
        self.all_data.append(row_data)
        self.table_data.append(row_data)

    def clear(self):
        self.all_data = []
        self.table_data = []
        self.selected_index = None
        self.body_canvas.delete("all")

    def filter(self, query):
        self.selected_index = None
        if not query:
            self.table_data = list(self.all_data)
        else:
            q = query.lower()
            self.table_data = [r for r in self.all_data 
                               if q in str(r.get('filename','')).lower() or 
                                  q in str(r.get('full_path','')).lower()]
        self.render()

    def sort_data(self, key):
        reverse = not self.current_sort["reverse"] if self.current_sort["col"] == key else False
        self.current_sort = {"col": key, "reverse": reverse}
        self.table_data.sort(key=lambda x: str(x.get(key, "")).lower(), reverse=reverse)
        self.selected_index = None
        self.render()

    # --- RENDER ENGINE ---
    def render(self):
        self.body_canvas.delete("all")
        self.row_map = {}
        self.index_map = {}
        current_y = 0
        
        # FIX: We enforce a simpler row height calculation to avoid glitches
        # We will wrap text, but hard-cap it at 3 lines.
        LINE_CAP = 3 
        
        for index, row in enumerate(self.table_data):
            # 1. Calculate Height
            max_lines = 1
            for col in self.columns:
                key = col["key"]
                text_val = str(row.get(key, ""))
                
                # SPECIAL HANDLING: Deep Output Column
                # We NEVER render the full report here. It breaks the UI.
                if key == "deep_output":
                    continue 

                width = col["width"] - 10
                if width > 0 and len(text_val) > 0:
                    chars = int(width / 7)
                    if chars < 1: chars = 1
                    wraps = math.ceil(len(text_val) / chars)
                    if wraps > max_lines: max_lines = wraps
            
            max_lines = min(max_lines, LINE_CAP)
            row_h = (max_lines * self.line_height) + 10
            
            # 2. Colors
            bg = "#252525" if index % 2 == 1 else ""
            fg = "#e0e0e0"
            verdict = row.get('verdict', '')
            threats = row.get('threats', '')
            
            if verdict == "LOCKED": bg, fg = "#152a4f", "#99badd"
            elif verdict == "SYNTHETIC" or "MACROS" in threats or "INJECTION" in threats: bg, fg = "#4a0e0e", "#ffcccc"
            elif "HIGH VELOCITY" in threats or "HIDDEN" in threats: bg, fg = "#4a3b0e", "#ffecb3"

            if index == self.selected_index: bg, fg = "#1F6AA5", "#FFFFFF"

            if bg:
                self.body_canvas.create_rectangle(0, current_y, self.total_width, current_y + row_h, fill=bg, outline="")

            # 3. Draw Text
            current_x = 0
            for col in self.columns:
                key = col["key"]
                
                # CLEAN DISPLAY LOGIC
                if key == "deep_output":
                    # Show a neat placeholder instead of matrix code
                    raw_val = row.get('deep_output_raw', '')
                    if raw_val:
                        line_count = len(raw_val.split('\n'))
                        text_val = f"📄 Report Ready ({line_count} lines)"
                    else:
                        text_val = ""
                else:
                    text_val = str(row.get(key, ""))

                cell_fg = fg
                if key == "is_duplicate" and text_val == "X" and index != self.selected_index:
                    cell_fg = "#ffffff" # White X

                self.body_canvas.create_text(current_x + 5, current_y + 5, 
                                             text=text_val, width=col["width"] - 10, 
                                             anchor="nw", fill=cell_fg, font=self.font_main)
                current_x += col["width"]

            self.row_map[(current_y, current_y + row_h)] = index
            self.index_map[index] = (current_y, current_y + row_h)
            current_y += row_h

        self.body_canvas.configure(scrollregion=(0, 0, self.total_width, current_y))

    # --- INPUT ---
    def _get_index(self, event):
        cy = self.body_canvas.canvasy(event.y)
        for (y1, y2), idx in self.row_map.items():
            if y1 <= cy < y2: return idx
        return None

    def _on_click(self, event):
        self.body_canvas.focus_set()
        idx = self._get_index(event)
        if idx is not None: 
            self.selected_index = idx
            self.render()
            self.on_double_click_callback(self.table_data[idx], is_single_click=True)

    def _on_arrow_up(self, event):
        if self.selected_index is not None and self.selected_index > 0:
            self._select_and_scroll(self.selected_index - 1)

    def _on_arrow_down(self, event):
        if self.table_data:
            if self.selected_index is None: self._select_and_scroll(0)
            elif self.selected_index < len(self.table_data) - 1:
                self._select_and_scroll(self.selected_index + 1)

    def _select_and_scroll(self, index):
        self.selected_index = index
        self.render()
        self.on_double_click_callback(self.table_data[index], is_single_click=True)
        if index in self.index_map:
            y1, y2 = self.index_map[index]
            h = self.body_canvas.winfo_height()
            top = self.body_canvas.canvasy(0)
            if y1 < top: self.body_canvas.yview_moveto(y1 / self.body_canvas.bbox("all")[3])
            elif y2 > top + h: self.body_canvas.yview_moveto((y2 - h + 20) / self.body_canvas.bbox("all")[3])

    def _on_double_click(self, event):
        idx = self._get_index(event)
        if idx is not None: self.on_double_click_callback(self.table_data[idx], is_single_click=False)

    def _on_right_click(self, event):
        self.body_canvas.focus_set()
        idx = self._get_index(event)
        if idx is not None: 
            self.selected_index = idx
            self.render()
            self.on_right_click_callback(event, self.table_data[idx], idx)