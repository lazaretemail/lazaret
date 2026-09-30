// SPDX-License-Identifier: AGPL-3.0-only

package oletools

import (
	"regexp"
	"strings"

	"github.com/lazaretemail/lazaret/mdm"
)

// The keyword table, and what risk it adds up to.
//
// Vocabulary and categories follow oletools, because the corpus is written against
// oletools: a rule saying `.type =~ "autoexec"` is naming olevba's category, and
// inventing different names here would leave that rule matching nothing while
// appearing to work.
//
// Two categories matter to the corpus and both are here:
//
//   - AutoExec — runs without the user doing anything beyond opening the document.
//     This is the one the auto-exec rule keys on, and on its own it is the
//     difference between a macro someone has to be talked into running and one that
//     runs on open.
//   - Suspicious — capabilities that legitimate document macros rarely need:
//     starting processes, writing files, downloading, reaching the registry.

// Keyword categories, spelled as olevba spells them. MQL's `=~` folds case, so a
// rule written against "autoexec" matches "AutoExec" — upstream's casing is kept.
const (
	typeAutoExec   = "AutoExec"
	typeSuspicious = "Suspicious"
)

// Risk levels, as oletools reports them.
const (
	riskNone   = "none"
	riskLow    = "low"
	riskMedium = "medium"
	riskHigh   = "high"
)

type keyword struct {
	word string
	kind string
	desc string
}

// autoExec are the entry points VBA calls by itself.
var autoExecKeywords = []keyword{
	{"AutoExec", typeAutoExec, "Runs when the Word document is opened"},
	{"AutoOpen", typeAutoExec, "Runs when the Word document is opened"},
	{"AutoClose", typeAutoExec, "Runs when the Word document is closed"},
	{"AutoExit", typeAutoExec, "Runs when Word exits"},
	{"AutoNew", typeAutoExec, "Runs when a new Word document is created"},
	{"Document_Open", typeAutoExec, "Runs when the Word or Publisher document is opened"},
	{"Document_Close", typeAutoExec, "Runs when the Word document is closed"},
	{"Document_BeforeClose", typeAutoExec, "Runs when the Word document is closed"},
	{"Document_New", typeAutoExec, "Runs when a new Word document is created"},
	{"DocumentOpen", typeAutoExec, "Runs when the Word document is opened"},
	{"Workbook_Open", typeAutoExec, "Runs when the Excel workbook is opened"},
	{"Workbook_Activate", typeAutoExec, "Runs when the Excel workbook is activated"},
	{"Workbook_Close", typeAutoExec, "Runs when the Excel workbook is closed"},
	{"Workbook_BeforeClose", typeAutoExec, "Runs when the Excel workbook is closed"},
	{"Auto_Open", typeAutoExec, "Runs when the Excel workbook is opened"},
	{"Auto_Close", typeAutoExec, "Runs when the Excel workbook is closed"},
	{"App_WorkbookOpen", typeAutoExec, "Runs when any Excel workbook is opened"},
	{"Worksheet_Activate", typeAutoExec, "Runs when the Excel worksheet is activated"},
	{"Worksheet_Change", typeAutoExec, "Runs when the Excel worksheet is changed"},
	{"Worksheet_SelectionChange", typeAutoExec, "Runs when the selection changes"},
	{"AutoRun", typeAutoExec, "Runs automatically"},
	{"Auto_Exec", typeAutoExec, "Runs automatically"},
}

// suspicious are capabilities. None is malicious by itself; several together in a
// document that arrived by email are the point.
var suspiciousKeywords = []keyword{
	{"Shell", typeSuspicious, "May run an executable file or a system command"},
	{"WScript.Shell", typeSuspicious, "May run an executable file or a system command"},
	{"Run", typeSuspicious, "May run an executable file or a system command"},
	{"ShellExecute", typeSuspicious, "May run an executable file or a system command"},
	{"CreateObject", typeSuspicious, "May create an OLE object"},
	{"GetObject", typeSuspicious, "May get an OLE object with a running instance"},
	{"Win32_Process", typeSuspicious, "May run a process through WMI"},
	{"powershell", typeSuspicious, "May run PowerShell commands"},
	{"cmd.exe", typeSuspicious, "May run a command shell"},
	{"mshta", typeSuspicious, "May run an HTML application"},
	{"rundll32", typeSuspicious, "May run a library export"},
	{"regsvr32", typeSuspicious, "May register and run a scriptlet"},
	{"URLDownloadToFile", typeSuspicious, "May download a file from the internet"},
	{"XMLHTTP", typeSuspicious, "May download a file from the internet"},
	{"WinHttpRequest", typeSuspicious, "May download a file from the internet"},
	{"ServerXMLHTTP", typeSuspicious, "May download a file from the internet"},
	{"ADODB.Stream", typeSuspicious, "May write to a file on disk"},
	{"SaveToFile", typeSuspicious, "May write to a file on disk"},
	{"FileSystemObject", typeSuspicious, "May read or write files"},
	{"Scripting.FileSystemObject", typeSuspicious, "May read or write files"},
	{"Open", typeSuspicious, "May open a file"},
	{"Write", typeSuspicious, "May write to a file"},
	{"Binary", typeSuspicious, "May read or write a file in binary mode"},
	{"Environ", typeSuspicious, "May read system environment variables"},
	{"RegWrite", typeSuspicious, "May write to the registry"},
	{"RegRead", typeSuspicious, "May read from the registry"},
	{"Call", typeSuspicious, "May call a library function"},
	{"Declare", typeSuspicious, "May define a library function"},
	{"CallByName", typeSuspicious, "May call a function by name"},
	{"VirtualAlloc", typeSuspicious, "May inject code into another process"},
	{"RtlMoveMemory", typeSuspicious, "May inject code into another process"},
	{"CreateThread", typeSuspicious, "May inject code into another process"},
	{"SetTimer", typeSuspicious, "May run code on a timer"},
	{"Chr", typeSuspicious, "May attempt to obfuscate strings"},
	{"ChrW", typeSuspicious, "May attempt to obfuscate strings"},
	{"StrReverse", typeSuspicious, "May attempt to obfuscate strings"},
	{"Xor", typeSuspicious, "May attempt to obfuscate strings"},
	{"Base64Decode", typeSuspicious, "May decode base64 strings"},
	{"Execute", typeSuspicious, "May run code built at runtime"},
	{"ExecuteGlobal", typeSuspicious, "May run code built at runtime"},
	{"Eval", typeSuspicious, "May run code built at runtime"},
	{"Vba.Interaction", typeSuspicious, "May run code built at runtime"},
}

// matchers are compiled once. Word boundaries matter: "Run" must not match inside
// "Runtime", and "Open" must not match inside "Document_Open" — the latter is an
// AutoExec hit and counting it twice would inflate the risk.
var matchers = buildMatchers()

type matcher struct {
	re *regexp.Regexp
	kw keyword
}

func buildMatchers() []matcher {
	all := append(append([]keyword{}, autoExecKeywords...), suspiciousKeywords...)
	out := make([]matcher, 0, len(all))
	for _, k := range all {
		// (?i) because VBA is case-insensitive and attackers know it.
		out = append(out, matcher{
			re: regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(k.word) + `\b`),
			kw: k,
		})
	}
	return out
}

// scanKeywords reports every keyword present, once each, in table order so the
// result is stable.
func scanKeywords(source string) []*mdm.OleKeyword {
	text := trimNonPrintable(source)
	var out []*mdm.OleKeyword
	seen := map[string]bool{}

	for _, m := range matchers {
		if seen[strings.ToLower(m.kw.word)] || !m.re.MatchString(text) {
			continue
		}
		seen[strings.ToLower(m.kw.word)] = true
		out = append(out, &mdm.OleKeyword{
			Type:        mdm.Ptr(m.kw.kind),
			Keyword:     mdm.Ptr(m.kw.word),
			Description: mdm.Ptr(m.kw.desc),
		})
	}
	return out
}

// riskOf grades a macro the way oletools does: what it can do, weighted by whether
// it needs a human to do it.
//
// The judgement that matters is the first one. A macro that runs on open and can
// start a process is the standard maldoc shape and is high; the same capabilities
// behind a button the user must press are a step down, because the document still
// has to talk them into it.
func riskOf(found []*mdm.OleKeyword) string {
	if len(found) == 0 {
		return riskNone
	}
	var auto, suspicious int
	for _, k := range found {
		switch mdm.Deref(k.Type) {
		case typeAutoExec:
			auto++
		case typeSuspicious:
			suspicious++
		}
	}

	switch {
	case auto > 0 && suspicious > 0:
		return riskHigh
	case suspicious >= 3:
		return riskHigh
	case auto > 0 || suspicious > 0:
		return riskMedium
	default:
		return riskLow
	}
}
