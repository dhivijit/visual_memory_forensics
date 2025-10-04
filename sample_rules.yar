/********************************************************************
  mem_dump_starter_rules.yar
  Starter rules for process memory / proc-dump analysis.
  - Designed for scanning ProcDump-produced .dmp files and carved regions.
  - Mix of byte, string, and regex detections for in-memory artifacts.
  - Author: (yours) — customize meta fields below.
********************************************************************/

/* ==================================================================
   Rule: InMemory_PE_Header
   Purpose: Find 'MZ' / PE headers located anywhere in the dump (i.e.,
            likely in-memory PE images that are not stored as files).
   Note: This uses uint16 checks across the file. It can be slow on
         very large files; run on carved regions or rely on pe-sieve first.
   ================================================================== */
rule InMemory_PE_Header
{
    meta:
        author = "starter-set"
        description = "Detect MZ/PE signatures located anywhere in file - useful to find in-memory PE images"
        confidence = 60
        created = "2025-10-02"

    /* plain MZ header at any offset (except 0) */
    condition:
        for any i in (1..filesize-2) : ( uint16(i) == 0x5A4D )
}

/* ==================================================================
   Rule: Suspicious_Shellcode_Prologue
   Purpose: Detect common shellcode prologues / assembler patterns often
            seen in Windows x86/x64 shellcode. Good for finding raw code.
   ================================================================== */
rule Suspicious_Shellcode_Prologue
{
    meta:
        author = "starter-set"
        description = "Common shellcode prologues and short getpc patterns"
        confidence = 65
        tags = ["shellcode","in-memory"]
    strings:
        $a1 = { 55 48 8B EC }            // push rbp; mov rbp, rsp (x64 prologue)
        $a2 = { 60 9C }                  // pushad; pushfd (old x86 shellcode)
        $a3 = { E8 ?? ?? ?? ?? 5B 59 }   // call <rel> ; pop pattern
        $a4 = { 48 31 C0 48 89 C2 48 89 C6 } // xor rax, rax; mov rax,r? etc
        $a5 = /getpc|call.*pop/i         // textual heuristics (if shellcode contains ASCII comments or patterns)
    condition:
        any of ($a*)
}

/* ==================================================================
   Rule: Suspicious_RWXPAGE_APIs
   Purpose: Look for text strings of API names & flags often used when
            allocating executable RWX memory or changing protections.
   Notes: Memory dumps often contain ASCII/UTF-16 representations of
          API names and constants (e.g., in stack frames or imports).
   ================================================================== */
rule Suspicious_RWXPAGE_APIs
{
    meta:
        author = "starter-set"
        description = "Detect API names / flags associated with RWX allocations or code injection"
        confidence = 70
        tags = ["api","rwx","injection"]
    strings:
        $s1 = "VirtualAlloc" ascii nocase
        $s2 = "VirtualAllocEx" ascii nocase
        $s3 = "VirtualProtect" ascii nocase
        $s4 = "WriteProcessMemory" ascii nocase
        $s5 = "CreateRemoteThread" ascii nocase
        $s6 = "PAGE_EXECUTE_READWRITE" ascii nocase
    condition:
        any of ($s*)
}

/* ==================================================================
   Rule: Suspicious_C2_Url
   Purpose: Catch obvious C2-like URLs (basic regex). Tune as needed.
   ================================================================== */
rule Suspicious_C2_Url
{
    meta:
        author = "starter-set"
        description = "Detect common HTTP(S) C2-style URL patterns"
        confidence = 75
        tags = ["ioc","url"]
    strings:
        $url = /https?:\/\/[A-Za-z0-9\-\._]+(:[0-9]{1,5})?(\/[^\s\"'<>]{1,200})?/ nocase
    condition:
        $url
}

/* ==================================================================
   Rule: Long_Base64_Block
   Purpose: Find long base64 blobs (often used for payloads, scripts,
            or staged binaries embedded as ascii). Common in memory.
   ================================================================== */
rule Long_Base64_Block
{
    meta:
        author = "starter-set"
        description = "Detect long base64-like blocks (>= 200 chars) - possible embedded payload"
        confidence = 60
        tags = ["base64","embedded"]
    strings:
        $b64 = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        $b64
}

/* ==================================================================
   Rule: Suspicious_DLL_Names
   Purpose: Match names often used by injectors/hookers or likely
            suspicious module names. Extend with your observed names.
   ================================================================== */
rule Suspicious_DLL_Names
{
    meta:
        author = "starter-set"
        description = "Detect suspicious/injection-like DLL names in memory"
        confidence = 60
        tags = ["dll","ioc"]
    strings:
        $d1 = "injector.dll" ascii nocase
        $d2 = "evilhook.dll" ascii nocase
        $d3 = "memoryhook.dll" ascii nocase
        $d4 = "svchostx.dll" ascii nocase
        $d5 = /[a-z0-9_]{3,50}\.dll/ nocase
    condition:
        1 of ($d1, $d2, $d3, $d4) or ( $d5 and filesize < 2000000 )
}

/* ==================================================================
   Rule: Powershell_EncodedCommand
   Purpose: Detect common PowerShell encoded command indicator often
            abused for in-memory execution (e.g., -EncodedCommand).
   Note: Useful if powershell command lines are present in memory.
   ================================================================== */
rule Powershell_EncodedCommand
{
    meta:
        author = "starter-set"
        description = "Detect 'EncodedCommand' or similar PowerShell constructs"
        confidence = 70
        tags = ["lolbas","powershell","evasion"]
    strings:
        $ps1 = "-EncodedCommand" ascii nocase
        $ps2 = "-e" ascii nocase
        $ps3 = "IEX" ascii nocase  // Invoke-Expression
    condition:
        any of ($ps*)
}

/* ==================================================================
   Rule: PE_File_Like_Section_Entropy (heuristic)
   Purpose: Identify regions that contain PE-like section names or
            characteristics (e.g., '.text', '.rsrc') combined with
            high-entropy sequences. This is heuristic and should be
            run on carved regions rather than on full huge dumps.
   ================================================================== */
rule PE_File_Like_Section_Entropy
{
    meta:
        author = "starter-set"
        description = "Heuristic: section names + base64/entropy-like content"
        confidence = 55
        tags = ["pe","heuristic","entropy"]
    strings:
        $sec_text = ".text" ascii nocase
        $sec_rsrc = ".rsrc" ascii nocase
        $high_entropy = /[A-Za-z0-9+\/]{80,}/
    condition:
        (any of ($sec_text, $sec_rsrc)) and $high_entropy
}
