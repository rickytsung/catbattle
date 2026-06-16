#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython
# LocateByXref.py
# @author Gemini
# @category Search
# @runtime Jython
# FindNewCellParse.py
# @author Gemini
# @category Search
# @runtime Jython

from ghidra.program.model.symbol import RefType

def find_cell_parse_by_xref():
    fm = currentProgram.getFunctionManager()
    rm = currentProgram.getReferenceManager()
    memory = currentProgram.getMemory()
    base_offset = currentProgram.getImageBase().getOffset()
    
    #  Ponos exclusive localized translation file signature string
    # This specific system file layout exists across all versions of Battle Cats.
    target_str = "GamatotoCollabo.tsv"
    
    print("------------------------------------------------------------------")
    print("[*] Initiating cross-version signature hunt for: " + target_str)
    
    # Step 1: Scan memory to locate the exact absolute address of the string
    search_bytes = bytearray(target_str, 'utf-8')
    start_addr = memory.getMinAddress()
    str_addr = memory.findBytes(start_addr, search_bytes, None, True, monitor)
    
    if str_addr is None:
        print("[-] Error: Could not find anchor string in this .so binary.")
        return
        
    print("[+] Found anchor string at absolute: " + hex(str_addr.getOffset()))
    
    # Step 2: Trace who references this string to reveal the parser entry point
    refs = rm.getReferencesTo(str_addr)
    for ref in refs:
        from_addr = ref.getFromAddress()
        parent_func = fm.getFunctionContaining(from_addr)
        
        if parent_func:
            # Step 3: We found the upper loader loop! Now dissect its calls.
            print("[+] Found Upper Table Loader function: " + parent_func.getName())
            print("[*] Scanning child calls inside this loop block...")
            
            # Get all sub-functions called by this table loader function
            called_addresses = parent_func.getCalledFunctions(monitor)
            
            for called_func in called_addresses:
                #  Golden Rule of Ponos Engine:
                # The core string utility sub-routine in cell_parse always has 
                # a high relative offset near the table loop and processes length tags.
                func_name = called_func.getName()
                func_entry = called_func.getEntryPoint().getOffset()
                calculated_rva = func_entry - base_offset
                
                # Filter out generic NDK standard library overrides
                if "std" not in func_name and "operator" not in func_name and "__stack" not in func_name:
                    print("    >> [POTENTIAL MATCH] Function: " + func_name)
                    print("       +-- CALCULATED RVA FOR YOUR NEW CODE: " + hex(calculated_rva))
                    print("------------------------------------------------------------------")
            return

    print("[-] Search finished. Look at the calculated RVA list above to upgrade your hook.")

print("=== STARTING AUTOMATED NEW VERSION ADDRESS DISCOVERY ===")
find_cell_parse_by_xref()
print("=== DISCOVERY TASK COMPLETED ===")
