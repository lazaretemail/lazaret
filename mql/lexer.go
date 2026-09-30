// SPDX-License-Identifier: AGPL-3.0-only

package mql

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Lexer turns MQL source into tokens.
//
// It is hand-written rather than generated, because the error messages are part of the
// product: a rule author who mistypes a field should get a caret under the right column,
// not a parser-generator's idea of an unexpected symbol.
//
// Newlines carry no meaning. Real rules break expressions across lines freely, including in
// the middle of a call's argument list and inside an array subscript, so nothing here is
// line-oriented.
type Lexer struct {
	src  string
	pos  int // byte offset of the next rune to read
	line int
	col  int

	errs ErrorList
}

// NewLexer prepares a lexer over src.
func NewLexer(src string) *Lexer {
	return &Lexer{src: src, line: 1, col: 1}
}

// Errors returns the errors encountered so far. Lexing is best-effort: an unterminated
// string or a bad escape is recorded and scanning continues, so that one typo does not hide
// every later problem in the same rule.
func (l *Lexer) Errors() ErrorList { return l.errs }

// Tokens scans the whole input. The final token is always EOF.
func (l *Lexer) Tokens() []Token {
	var toks []Token
	for {
		t := l.Next()
		toks = append(toks, t)
		if t.Kind == EOF {
			return toks
		}
	}
}

// Next returns the next token.
func (l *Lexer) Next() Token {
	l.skipSpaceAndComments()
	pos := l.here()

	if l.pos >= len(l.src) {
		return Token{Kind: EOF, Pos: pos}
	}

	r, size := utf8.DecodeRuneInString(l.src[l.pos:])

	switch {
	case r == '"':
		return l.lexEscapedString(pos)
	case r == '\'':
		return l.lexRawString(pos)
	case r == '$':
		return l.lexList(pos)
	case unicode.IsDigit(r):
		return l.lexNumber(pos)
	case isIdentStart(r):
		return l.lexIdent(pos)
	}

	l.advance(r, size)
	simple := func(k Kind) Token {
		return Token{Kind: k, Pos: pos, Text: string(r)}
	}

	switch r {
	case '.':
		return simple(Dot)
	case ',':
		return simple(Comma)
	case ':':
		return simple(Colon)
	case '(':
		return simple(LParen)
	case ')':
		return simple(RParen)
	case '[':
		return simple(LBracket)
	case ']':
		return simple(RBracket)
	case '+':
		return simple(Plus)
	case '-':
		return simple(Minus)
	case '*':
		return simple(Star)
	case '/':
		return simple(Slash)
	case '%':
		return simple(Percent)

	case '=':
		switch l.at(0) {
		case '=':
			return l.two(Eq, pos, "==")
		case '~':
			return l.two(IEq, pos, "=~")
		}
		// A bare "=" is a keyword argument, as in ml.link_analysis(., mode="aggressive").
		return simple(Assign)

	case '!':
		switch l.at(0) {
		case '=':
			return l.two(NotEq, pos, "!=")
		case '~':
			return l.two(INotEq, pos, "!~")
		}
		l.errorf(pos, "unexpected %q; did you mean != or !~, or the keyword not?", "!")
		return Token{Kind: Invalid, Pos: pos, Text: "!"}

	case '<':
		if l.at(0) == '=' {
			return l.two(LtEq, pos, "<=")
		}
		return simple(Lt)

	case '>':
		if l.at(0) == '=' {
			return l.two(GtEq, pos, ">=")
		}
		return simple(Gt)
	}

	l.errorf(pos, "unexpected character %q", r)
	return Token{Kind: Invalid, Pos: pos, Text: string(r)}
}

// two consumes a second byte and returns a two-character operator token.
func (l *Lexer) two(k Kind, pos Pos, text string) Token {
	l.advance(rune(text[1]), 1)
	return Token{Kind: k, Pos: pos, Text: text}
}

func (l *Lexer) skipSpaceAndComments() {
	for l.pos < len(l.src) {
		r, size := utf8.DecodeRuneInString(l.src[l.pos:])
		switch {
		case unicode.IsSpace(r):
			l.advance(r, size)
		case r == '/' && l.at(1) == '/':
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				r, size := utf8.DecodeRuneInString(l.src[l.pos:])
				l.advance(r, size)
			}
		default:
			return
		}
	}
}

func (l *Lexer) lexIdent(pos Pos) Token {
	start := l.pos
	for l.pos < len(l.src) {
		r, size := utf8.DecodeRuneInString(l.src[l.pos:])
		if !isIdentPart(r) {
			break
		}
		l.advance(r, size)
	}
	text := l.src[start:l.pos]

	if k, ok := keywords[text]; ok {
		// "in~" is the case-insensitive membership operator. It is the only keyword with a
		// suffix, so it is handled here rather than in the operator switch.
		if k == In && l.at(0) == '~' {
			l.advance('~', 1)
			return Token{Kind: IIn, Pos: pos, Text: "in~"}
		}
		return Token{Kind: k, Pos: pos, Text: text}
	}
	return Token{Kind: Ident, Pos: pos, Text: text}
}

func (l *Lexer) lexList(pos Pos) Token {
	l.advance('$', 1) // consume the sigil
	start := l.pos
	for l.pos < len(l.src) {
		r, size := utf8.DecodeRuneInString(l.src[l.pos:])
		if !isIdentPart(r) {
			break
		}
		l.advance(r, size)
	}
	name := l.src[start:l.pos]
	if name == "" {
		l.errorf(pos, "expected a list name after $")
		return Token{Kind: Invalid, Pos: pos, Text: "$"}
	}
	return Token{Kind: List, Pos: pos, Text: "$" + name, Value: name}
}

func (l *Lexer) lexNumber(pos Pos) Token {
	start := l.pos
	kind := Int
	for l.pos < len(l.src) {
		r, size := utf8.DecodeRuneInString(l.src[l.pos:])
		if unicode.IsDigit(r) {
			l.advance(r, size)
			continue
		}
		// A dot is only part of the number when a digit follows it. Otherwise it is field
		// access or a slice colon's neighbour, as in attachments[0].file_type.
		if r == '.' && kind == Int && l.at(1) != 0 && isASCIIDigit(l.at(1)) {
			kind = Float
			l.advance(r, size)
			continue
		}
		break
	}
	return Token{Kind: kind, Pos: pos, Text: l.src[start:l.pos]}
}

// lexEscapedString scans a double-quoted string, which supports escape sequences.
func (l *Lexer) lexEscapedString(pos Pos) Token {
	start := l.pos
	l.advance('"', 1)

	var b strings.Builder
	for {
		if l.pos >= len(l.src) {
			l.errorf(pos, "unterminated string")
			return Token{Kind: Invalid, Pos: pos, Text: l.src[start:l.pos]}
		}
		r, size := utf8.DecodeRuneInString(l.src[l.pos:])
		if r == '"' {
			l.advance(r, size)
			return Token{Kind: String, Pos: pos, Text: l.src[start:l.pos], Value: b.String()}
		}
		if r != '\\' {
			l.advance(r, size)
			b.WriteRune(r)
			continue
		}

		escPos := l.here()
		l.advance(r, size)
		if l.pos >= len(l.src) {
			l.errorf(pos, "unterminated string")
			return Token{Kind: Invalid, Pos: pos, Text: l.src[start:l.pos]}
		}
		e, esize := utf8.DecodeRuneInString(l.src[l.pos:])
		l.advance(e, esize)
		switch e {
		case 'r':
			b.WriteByte('\r')
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case '\'':
			b.WriteByte('\'')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case 'u':
			if cp, ok := l.lexUnicodeEscape(escPos); ok {
				b.WriteRune(cp)
			}
		default:
			// Documented behaviour: an unrecognised escape is a syntax error, not a literal
			// backslash. Rules that want a literal backslash use a raw string.
			l.errorf(escPos, "invalid escape sequence %q", `\`+string(e))
		}
	}
}

// lexUnicodeEscape reads the {xxxxxxxx} of a \u escape, already past the 'u'.
func (l *Lexer) lexUnicodeEscape(escPos Pos) (rune, bool) {
	if l.at(0) != '{' {
		l.errorf(escPos, `\u must be followed by a code point in braces, as in \u{1f4ec}`)
		return 0, false
	}
	l.advance('{', 1)

	var cp rune
	digits := 0
	for l.pos < len(l.src) && l.src[l.pos] != '}' {
		d, ok := hexValue(l.src[l.pos])
		if !ok {
			l.errorf(escPos, "invalid hex digit %q in unicode escape", l.src[l.pos])
			return 0, false
		}
		cp = cp<<4 | rune(d)
		digits++
		if digits > 8 {
			l.errorf(escPos, "unicode escape has more than 8 hex digits")
			return 0, false
		}
		l.advance(rune(l.src[l.pos]), 1)
	}
	if l.pos >= len(l.src) {
		l.errorf(escPos, "unterminated unicode escape: missing }")
		return 0, false
	}
	l.advance('}', 1)

	if digits < 2 {
		l.errorf(escPos, "unicode escape needs at least 2 hex digits")
		return 0, false
	}
	if cp < 1 || cp > unicode.MaxRune {
		l.errorf(escPos, "unicode code point %#x is out of range", cp)
		return 0, false
	}
	return cp, true
}

// lexRawString scans a single-quoted string.
//
// Raw strings have no escape sequences at all: ” is the only special sequence and produces
// one quote. This is load-bearing rather than pedantic — the public corpus contains the
// literal '\', a raw string holding a single backslash. A lexer that treated \' as an
// escaped quote would swallow the terminator and mis-parse the rest of the rule.
func (l *Lexer) lexRawString(pos Pos) Token {
	start := l.pos
	l.advance('\'', 1)

	var b strings.Builder
	for {
		if l.pos >= len(l.src) {
			l.errorf(pos, "unterminated string")
			return Token{Kind: Invalid, Pos: pos, Text: l.src[start:l.pos]}
		}
		r, size := utf8.DecodeRuneInString(l.src[l.pos:])
		if r != '\'' {
			l.advance(r, size)
			b.WriteRune(r)
			continue
		}
		l.advance(r, size)
		if l.at(0) == '\'' {
			l.advance('\'', 1)
			b.WriteByte('\'')
			continue
		}
		return Token{Kind: String, Pos: pos, Text: l.src[start:l.pos], Value: b.String()}
	}
}

// advance consumes one rune, maintaining the line and column counters.
func (l *Lexer) advance(r rune, size int) {
	l.pos += size
	if r == '\n' {
		l.line++
		l.col = 1
		return
	}
	l.col++
}

func (l *Lexer) here() Pos { return Pos{Offset: l.pos, Line: l.line, Column: l.col} }

// at returns the byte n positions ahead of the cursor, or 0 past the end of input.
//
// Callers must be clear about where the cursor is: at(0) is the byte under it, which after
// advance() is the one *after* the rune just consumed. Getting this wrong silently breaks
// two-character operators, since "=" followed by "~" then scans as two separate tokens.
func (l *Lexer) at(n int) byte {
	if l.pos+n >= len(l.src) {
		return 0
	}
	return l.src[l.pos+n]
}

func (l *Lexer) errorf(pos Pos, format string, args ...any) {
	l.errs = append(l.errs, &Error{Pos: pos, Msg: fmt.Sprintf(format, args...)})
}

func isIdentStart(r rune) bool {
	return r == '_' || unicode.IsLetter(r)
}

func isIdentPart(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

func hexValue(b byte) (int, bool) {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0'), true
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10, true
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10, true
	}
	return 0, false
}
