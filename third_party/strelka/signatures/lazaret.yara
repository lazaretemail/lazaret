// Lazaret's YARA signatures, loaded by Strelka's ScanYara over every file an explosion
// produces — archive members, embedded objects, decoded scripts — not just the attachment
// that arrived. Matches surface in MQL at `.scan.yara.matches`.
//
// This directory is mounted over /etc/strelka/yara, replacing upstream's placeholder
// (`rule test { condition: true }`, which matches everything). ScanYara compiles the
// directory recursively, so additional .yara files here are picked up with no config
// change, and the same directory is what `lazaret yara` reads — a signature behaves
// identically whether it runs inside an explosion or over a top-level attachment.
//
// Keep rules cheap and specific. They run against every node of every message.

rule lazaret_script_obfuscation
{
    meta:
        author      = "Lazaret"
        description = "Script that builds and runs code at runtime — common to attachment droppers"

    strings:
        $eval     = "eval(" ascii nocase
        $unescape = "unescape(" ascii nocase
        $fromchar = "fromCharCode" ascii nocase
        $wscript  = "WScript.Shell" ascii nocase
        $activex  = "ActiveXObject" ascii nocase

    condition:
        2 of them
}

rule lazaret_ole_auto_exec
{
    meta:
        author      = "Lazaret"
        description = "Office macro that runs on open, without user interaction"

    strings:
        $a = "AutoOpen"      ascii nocase
        $b = "Auto_Open"     ascii nocase
        $c = "Workbook_Open" ascii nocase
        $d = "Document_Open" ascii nocase
        $e = "AutoExec"      ascii nocase

    condition:
        any of them
}
