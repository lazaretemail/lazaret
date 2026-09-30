// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"regexp"
	"strings"
)

// MacroClassifier answers ml.macro_classifier.
//
// Features rather than a model, and here that is the stronger choice rather than a
// fallback. What makes a VBA macro malicious is not a matter of tone: it runs without
// being asked, it reaches the network or the shell, and it hides what it is doing.
// Those are three observable properties of the source, each individually rare in a
// legitimate document macro and jointly almost unheard of.
//
// The corpus reads `.malicious` together with `.confidence in ("high")`, so a finding
// that is not confident changes no verdict. The scoring is built around that: only a
// macro exhibiting behaviour from more than one family reaches high.
type MacroClassifier struct{}

func (MacroClassifier) Capability() string { return "ml.macro_classifier" }
func (MacroClassifier) Close() error       { return nil }

type macroResult struct {
	Malicious  bool     `json:"malicious"`
	Confidence string   `json:"confidence"`
	Score      float64  `json:"score"`
	Indicators []string `json:"indicators,omitempty"`
}

// The families. Grouped because the grouping is the signal: AutoOpen alone is a macro
// that runs on open, which is ordinary; AutoOpen plus Shell plus a decoder loop is not.
var macroFamilies = []struct {
	family   string
	weight   float64
	patterns map[string]*regexp.Regexp
}{
	{"autorun", 2.0, map[string]*regexp.Regexp{
		"AutoOpen":          regexp.MustCompile(`(?i)\bSub\s+AutoOpen\b`),
		"AutoClose":         regexp.MustCompile(`(?i)\bSub\s+AutoClose\b`),
		"Document_Open":     regexp.MustCompile(`(?i)\bSub\s+Document_Open\b`),
		"Workbook_Open":     regexp.MustCompile(`(?i)\bSub\s+Workbook_Open\b`),
		"Auto_Open":         regexp.MustCompile(`(?i)\bSub\s+Auto_Open\b`),
		"Document_Close":    regexp.MustCompile(`(?i)\bSub\s+Document_Close\b`),
		"InkPicture_Paint":  regexp.MustCompile(`(?i)\bSub\s+\w*_Paint\b`),
		"Frame_Layout":      regexp.MustCompile(`(?i)\bSub\s+\w*_Layout\b`),
		"Application_Start": regexp.MustCompile(`(?i)\bSub\s+\w*_(?:Activate|Startup|Change)\b`),
	}},
	{"execution", 3.0, map[string]*regexp.Regexp{
		"Shell":            regexp.MustCompile(`(?i)\bShell\s*\(`),
		"WScript.Shell":    regexp.MustCompile(`(?i)WScript\.Shell`),
		"CreateObject":     regexp.MustCompile(`(?i)\bCreateObject\s*\(`),
		"GetObject":        regexp.MustCompile(`(?i)\bGetObject\s*\(`),
		"WMI":              regexp.MustCompile(`(?i)winmgmts:|Win32_Process`),
		"powershell":       regexp.MustCompile(`(?i)\bpowershell(?:\.exe)?\b|\bpwsh\b`),
		"cmd.exe":          regexp.MustCompile(`(?i)\bcmd(?:\.exe)?\s*/[ck]\b`),
		"mshta":            regexp.MustCompile(`(?i)\bmshta\b|\brundll32\b|\bregsvr32\b|\bcertutil\b`),
		"ShellExecute":     regexp.MustCompile(`(?i)\bShellExecute(?:A|W)?\b`),
		"Declare Lib":      regexp.MustCompile(`(?i)\bDeclare\s+(?:PtrSafe\s+)?(?:Sub|Function)\b[^\n]*\bLib\b`),
		"VBA.CreateObject": regexp.MustCompile(`(?i)VBA\.CreateObject`),
	}},
	{"network", 3.0, map[string]*regexp.Regexp{
		"XMLHTTP":            regexp.MustCompile(`(?i)(?:MSXML2\.)?(?:Server)?XMLHTTP|WinHttp\.WinHttpRequest`),
		"URLDownloadToFile":  regexp.MustCompile(`(?i)\bURLDownloadToFile(?:A|W)?\b`),
		"InternetExplorer":   regexp.MustCompile(`(?i)InternetExplorer\.Application`),
		"ADODB.Stream":       regexp.MustCompile(`(?i)ADODB\.Stream`),
		"http literal":       regexp.MustCompile(`(?i)"https?://`),
		"Microsoft.XMLHTTP":  regexp.MustCompile(`(?i)Microsoft\.XMLHTTP`),
		"BITS":               regexp.MustCompile(`(?i)\bbitsadmin\b|BackgroundCopyManager`),
		"DownloadString":     regexp.MustCompile(`(?i)DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b`),
		"Scripting.FileSys":  regexp.MustCompile(`(?i)Scripting\.FileSystemObject`),
		"Environ TEMP write": regexp.MustCompile(`(?i)Environ\s*\(\s*"(?:TEMP|APPDATA|TMP|USERPROFILE)"`),
	}},
	{"obfuscation", 2.5, map[string]*regexp.Regexp{
		"Chr concatenation": regexp.MustCompile(`(?i)(?:Chr[W$]?\s*\(\s*\d+\s*\)\s*&\s*){4,}`),
		"StrReverse":        regexp.MustCompile(`(?i)\bStrReverse\s*\(`),
		"Base64 decode":     regexp.MustCompile(`(?i)FromBase64String|MSXML2\.DOMDocument|bin\.base64`),
		"Xor loop":          regexp.MustCompile(`(?i)\bXor\b[^\n]{0,40}\bAsc\b|\bAsc\b[^\n]{0,40}\bXor\b`),
		"Hex literals":      regexp.MustCompile(`(?:&H[0-9A-Fa-f]{2}\s*,?\s*){8,}`),
		"Execute":           regexp.MustCompile(`(?i)\bExecute(?:Global)?\s*\(|\bEval\s*\(`),
		"Replace chain":     regexp.MustCompile(`(?i)(?:Replace\s*\([^\n]{0,60}){3,}`),
		"long string":       regexp.MustCompile(`"[A-Za-z0-9+/=]{300,}"`),
		"CallByName":        regexp.MustCompile(`(?i)\bCallByName\b`),
	}},
	{"evasion", 2.0, map[string]*regexp.Regexp{
		"sandbox check":    regexp.MustCompile(`(?i)\b(?:VirtualBox|VMware|QEMU|Sandboxie|wireshark|SbieDll)\b`),
		"recent files":     regexp.MustCompile(`(?i)RecentFiles\.Count`),
		"mouse check":      regexp.MustCompile(`(?i)\bGetCursorPos\b|Application\.MouseAvailable`),
		"sleep":            regexp.MustCompile(`(?i)\bApplication\.Wait\b|\bSleep\s+\d{4,}`),
		"disable security": regexp.MustCompile(`(?i)AutomationSecurity|EnableEvents\s*=\s*False|DisplayAlerts\s*=\s*False|AccessVBOM|VBAWarnings`),
		"self-delete":      regexp.MustCompile(`(?i)Kill\s+(?:ThisDocument|Application)\.FullName`),
	}},
	{"persistence", 1.5, map[string]*regexp.Regexp{
		"registry write": regexp.MustCompile(`(?i)RegWrite|HKEY_(?:CURRENT_USER|LOCAL_MACHINE)`),
		"startup folder": regexp.MustCompile(`(?i)\\Start Menu\\Programs\\Startup|\\Startup\\`),
		"scheduled task": regexp.MustCompile(`(?i)\bschtasks\b|Schedule\.Service`),
		"normal.dotm":    regexp.MustCompile(`(?i)Normal\.dotm?\b`),
	}},
}

func (MacroClassifier) Infer(ctx context.Context, req Request) (any, error) {
	src := req.Text
	if src == "" && len(req.Image) > 0 {
		// Some callers send the file bytes rather than extracted source. VBA in an
		// OLE stream is still mostly readable text, so scanning it directly is
		// better than refusing, and the patterns are anchored enough not to fire on
		// arbitrary binary.
		src = string(req.Image)
	}
	if strings.TrimSpace(src) == "" {
		return macroResult{Malicious: false, Confidence: ConfLow}, nil
	}
	if len(src) > 4<<20 {
		src = src[:4<<20]
	}

	score := 0.0
	families := 0
	var indicators []string
	for _, f := range macroFamilies {
		hit := false
		for name, re := range f.patterns {
			if re.MatchString(src) {
				if !hit {
					families++
					hit = true
				}
				indicators = append(indicators, f.family+":"+name)
			}
		}
		if hit {
			score += f.weight
		}
	}

	// A single family is a macro doing one thing, and plenty of legitimate macros do
	// exactly one of these. Two families is a macro that runs by itself and then
	// reaches outside the document, which is the shape that matters.
	res := macroResult{Score: score, Indicators: indicators}
	switch {
	case families >= 3 && score >= 7:
		res.Malicious, res.Confidence = true, ConfHigh
	case families >= 2 && score >= 5:
		res.Malicious, res.Confidence = true, ConfMedium
	case families >= 1:
		res.Malicious, res.Confidence = false, ConfLow
	default:
		res.Malicious, res.Confidence = false, ConfHigh
	}
	return res, nil
}
