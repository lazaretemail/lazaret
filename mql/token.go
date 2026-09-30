// SPDX-License-Identifier: AGPL-3.0-only

package mql

import "fmt"

// Kind classifies a lexical token.
type Kind uint8

const (
	EOF Kind = iota
	Invalid

	// Literals and names.
	Ident  // sender, strings, any
	Int    // 42
	Float  // 3.14
	String // "text" or 'text'
	List   // $org_domains

	// Punctuation.
	Dot      // .
	Comma    // ,
	Colon    // :
	LParen   // (
	RParen   // )
	LBracket // [
	RBracket // ]
	Assign   // = in a keyword argument

	// Operators.
	Eq      // ==
	NotEq   // !=
	IEq     // =~
	INotEq  // !~
	Lt      // <
	LtEq    // <=
	Gt      // >
	GtEq    // >=
	Plus    // +
	Minus   // -
	Star    // *
	Slash   // /
	Percent // %

	// Keywords.
	And
	Or
	Not
	In  // in
	IIn // in~
	Of
	Is
	Null
	True
	False
)

var kindNames = [...]string{
	EOF: "end of input", Invalid: "invalid token",
	Ident: "identifier", Int: "integer", Float: "float", String: "string", List: "list",
	Dot: `"."`, Comma: `","`, Colon: `":"`, LParen: `"("`, RParen: `")"`,
	LBracket: `"["`, RBracket: `"]"`, Assign: `"="`,
	Eq: `"=="`, NotEq: `"!="`, IEq: `"=~"`, INotEq: `"!~"`,
	Lt: `"<"`, LtEq: `"<="`, Gt: `">"`, GtEq: `">="`,
	Plus: `"+"`, Minus: `"-"`, Star: `"*"`, Slash: `"/"`, Percent: `"%"`,
	And: `"and"`, Or: `"or"`, Not: `"not"`, In: `"in"`, IIn: `"in~"`, Of: `"of"`,
	Is: `"is"`, Null: `"null"`, True: `"true"`, False: `"false"`,
}

func (k Kind) String() string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return fmt.Sprintf("token(%d)", uint8(k))
}

// keywords are matched case-sensitively. MQL is case-sensitive elsewhere, and the public
// corpus never writes "AND" or "Not", so accepting them would invent a dialect.
var keywords = map[string]Kind{
	"and":   And,
	"or":    Or,
	"not":   Not,
	"in":    In,
	"of":    Of,
	"is":    Is,
	"null":  Null,
	"true":  True,
	"false": False,
}

// Pos locates a token in the source. Offset is a byte index; Line and Column are 1-based,
// and Column counts runes so that a caret lines up under the offending token when the
// source contains multi-byte characters — which rules routinely do, since they match on
// homoglyphs and emoji.
type Pos struct {
	Offset int
	Line   int
	Column int
}

func (p Pos) String() string { return fmt.Sprintf("%d:%d", p.Line, p.Column) }

// Token is one lexeme.
type Token struct {
	Kind Kind
	Pos  Pos

	// Text is the source text of the token, unprocessed. For strings this includes the
	// quotes; use Value for the decoded contents.
	Text string

	// Value holds the decoded payload: the unescaped contents of a string, or the name of a
	// $list without its sigil. Empty for every other kind.
	Value string
}

func (t Token) String() string {
	if t.Text != "" {
		return fmt.Sprintf("%s %q at %s", t.Kind, t.Text, t.Pos)
	}
	return fmt.Sprintf("%s at %s", t.Kind, t.Pos)
}
