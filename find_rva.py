#TODO write a description for this script
#@author 
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


#TODO Add User Code Here
# Search for CSV/TSV references and aggregate them into a clean, unique function list.
# @author Gemini
# @category Search
# Comprehensive search for all asset keywords with explicit RVA math verification.
# @author Gemini
# @category Search

def verify_all_asset_rvas():
    fm = currentProgram.getFunctionManager()
    rm = currentProgram.getReferenceManager()
    memory = currentProgram.getMemory()
    
    
    base_addr_obj = currentProgram.getImageBase()
    base_offset = base_addr_obj.getOffset()

    print("==================================================================")
    print("===         Battle Cats Deep Asset RVA Verification            ===")
    print("==================================================================")
    print("[*] Ghidra Current Image Base: 0x{:X}".format(base_offset))
    print("[*] RVA Calculation Formula: [Absolute Address] - [Image Base]")
    print("==================================================================")

    target_keywords = [".csv", ".list", ".tsv", ".pack", "DataLocal", "resLocal"]

    for kw in target_keywords:
        print("\n[+] Scanning for Keyword: '{}'".format(kw))
        search_bytes = bytearray(kw, 'utf-8')
        start_addr = memory.getMinAddress()
        
        match_count = 0
        while True:
            if monitor.isCancelled():
                print("[-] Scan cancelled by user.")
                return
                
         
            addr = memory.findBytes(start_addr, search_bytes, None, True, monitor)
            if addr is None:
                break
                
            match_count += 1
            str_absolute = addr.getOffset()
            str_rva = str_absolute - base_offset
            
            print("  -> Found String Absolute Addr: 0x{:X} | Calculated RVA: 0x{:X}".format(str_absolute, str_rva))

            # 
            refs = rm.getReferencesTo(addr)
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = fm.getFunctionContaining(from_addr)
                
                if func:
                    func_entry = func.getEntryPoint()
                    func_absolute = func_entry.getOffset()
                    # 
                    func_rva = func_absolute - base_offset
                    
                    print("     [!] XREF MATCH -> Function Name: {}".format(func.getName()))
                    print("         |-- Call Site Addr : 0x{:X}".format(from_addr.getOffset()))
                    print("         |-- Func Entry Addr: 0x{:X}".format(func_absolute))
                    print("         +-- VERIFIED RVA   : 0x{:X}  (0x{:X} - 0x{:X})".format(
                        func_rva, func_absolute, base_offset
                    ))
                else:
                    print("     [?] XREF Outside Function at Addr: 0x{:X}".format(from_addr.getOffset()))
            
            start_addr = addr.add(1)
            
        if match_count == 0:
            print("  -> No occurrences found.")

    print("\n==================================================================")
    print("===                 Verification Scan Finished                 ===")
    print("==================================================================")


verify_all_asset_rvas()
