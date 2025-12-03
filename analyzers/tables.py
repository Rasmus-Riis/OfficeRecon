from utils.helpers import NS, log_info, log_warning, log_success

class TableAnalyzer:
    def __init__(self, loader):
        self.loader = loader
        self.tables = []

    def run(self):
        print("\n--- Table Structure Analysis ---")
        self._extract_tables()
        self._analyze_tables()

    def _extract_tables(self):
        """Extract all tables and their properties."""
        tree = self.loader.get_xml_tree('word/document.xml')
        if not tree:
            return

        tables = tree.xpath('//w:tbl', namespaces=NS)
        
        for table_idx, table in enumerate(tables):
            # Get table properties
            tbl_pr = table.xpath('.//w:tblPr', namespaces=NS)
            
            # Count rows and columns
            rows = table.xpath('.//w:tr', namespaces=NS)
            num_rows = len(rows)
            
            # Get max column count
            max_cols = 0
            for row in rows:
                cells = row.xpath('.//w:tc', namespaces=NS)
                max_cols = max(max_cols, len(cells))
            
            table_info = {
                'index': table_idx + 1,
                'rows': num_rows,
                'cols': max_cols,
                'hidden_cells': [],
                'merged_cells': [],
                'properties': {}
            }
            
            # Check for hidden or empty cells
            for row_idx, row in enumerate(rows):
                cells = row.xpath('.//w:tc', namespaces=NS)
                for cell_idx, cell in enumerate(cells):
                    # Check for hidden content
                    vanish = cell.xpath('.//w:vanish', namespaces=NS)
                    if vanish:
                        table_info['hidden_cells'].append({
                            'row': row_idx + 1,
                            'col': cell_idx + 1
                        })
                    
                    # Check for merged cells (gridSpan, vMerge)
                    grid_span = cell.xpath('.//w:gridSpan', namespaces=NS)
                    v_merge = cell.xpath('.//w:vMerge', namespaces=NS)
                    
                    if grid_span or v_merge:
                        merge_info = {}
                        if grid_span:
                            merge_info['horizontal'] = grid_span[0].get(f"{{{NS['w']}}}val", '1')
                        if v_merge:
                            merge_val = v_merge[0].get(f"{{{NS['w']}}}val", 'continue')
                            merge_info['vertical'] = merge_val
                        
                        table_info['merged_cells'].append({
                            'row': row_idx + 1,
                            'col': cell_idx + 1,
                            'merge': merge_info
                        })
            
            # Get table style
            if tbl_pr:
                tbl_style = tbl_pr[0].xpath('.//w:tblStyle', namespaces=NS)
                if tbl_style:
                    table_info['properties']['style'] = tbl_style[0].get(f"{{{NS['w']}}}val", '')
                
                # Check if table is hidden
                tbl_hidden = tbl_pr[0].xpath('.//w:tblpPr', namespaces=NS)
                if tbl_hidden:
                    table_info['properties']['positioned'] = True
            
            self.tables.append(table_info)

    def _analyze_tables(self):
        """Analyze tables for forensic significance."""
        if not self.tables:
            log_success("No tables found in document.")
            return
        
        log_info(f"Found {len(self.tables)} table(s)")
        
        for table in self.tables:
            print(f"\n[TABLE {table['index']}]: {table['rows']} rows × {table['cols']} columns")
            
            if table['properties'].get('style'):
                print(f"  Style: {table['properties']['style']}")
            
            if table['properties'].get('positioned'):
                log_warning("  [POSITIONED] Table has absolute positioning (may be hidden)")
            
            if table['hidden_cells']:
                log_warning(f"  [HIDDEN CELLS]: {len(table['hidden_cells'])} cell(s) with hidden content")
                for cell in table['hidden_cells'][:5]:
                    print(f"    • Cell ({cell['row']}, {cell['col']})")
            
            if table['merged_cells']:
                log_info(f"  Merged cells: {len(table['merged_cells'])}")
                # Show significant merges (spanning multiple rows/cols)
                significant = [m for m in table['merged_cells'] 
                              if ('horizontal' in m['merge'] and int(m['merge']['horizontal']) > 2)]
                if significant:
                    for merge in significant[:3]:
                        print(f"    • Cell ({merge['row']}, {merge['col']}) spans {merge['merge'].get('horizontal', 1)} columns")
