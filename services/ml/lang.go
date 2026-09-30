// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"sort"
	"strings"
	"unicode"
)

// Language identification, without a model.
//
// The names are the contract and they are not ISO codes. The corpus compares
// `.language == "english"`, `!= "japanese"`, `== "french"` — lowercase English names.
// Returning "en" here would be defensible and would match nothing, which is the worse
// kind of wrong: every rule gated on language would quietly stop working and no error
// would be raised anywhere.
//
// Two stages, because they answer different questions. Script settles the languages
// that have their own writing system: text in Hiragana is Japanese and no frequency
// table is needed to say so. Latin script does need one, and stopword frequency is
// used rather than character n-grams because the stopword lists are short enough to
// read and check, and a wrong answer can be traced to a word rather than to a weight.
func detectLanguage(text string) (string, float64) {
	if len(text) > 64<<10 {
		text = text[:64<<10]
	}
	runes := []rune(text)
	if len(runes) == 0 {
		return "", 0
	}

	counts := map[string]int{}
	letters := 0
	for _, r := range runes {
		if !unicode.IsLetter(r) {
			continue
		}
		letters++
		switch {
		case unicode.Is(unicode.Hiragana, r), unicode.Is(unicode.Katakana, r):
			counts["japanese"] += 3 // decisive: kana are not shared with Chinese
		case unicode.Is(unicode.Hangul, r):
			counts["korean"] += 3
		case unicode.Is(unicode.Han, r):
			counts["han"]++ // ambiguous between Chinese and Japanese until kana decide
		case unicode.Is(unicode.Cyrillic, r):
			counts["cyrillic"]++
		case unicode.Is(unicode.Greek, r):
			counts["greek"]++
		case unicode.Is(unicode.Arabic, r):
			counts["arabic"]++
		case unicode.Is(unicode.Hebrew, r):
			counts["hebrew"]++
		case unicode.Is(unicode.Thai, r):
			counts["thai"]++
		case unicode.Is(unicode.Devanagari, r):
			counts["hindi"]++
		case unicode.Is(unicode.Latin, r):
			counts["latin"]++
		}
	}
	if letters == 0 {
		return "", 0
	}

	// Kana anywhere settles Japanese, even in text that is mostly Han.
	if counts["japanese"] > 0 && counts["japanese"]*10 >= letters {
		return "japanese", 0.95
	}
	for script, lang := range map[string]string{
		"korean": "korean", "han": "chinese", "cyrillic": "russian", "greek": "greek",
		"arabic": "arabic", "hebrew": "hebrew", "thai": "thai", "hindi": "hindi",
	} {
		if counts[script]*2 > letters {
			// Cyrillic is Russian only by weight of use; Ukrainian, Bulgarian and
			// Serbian share the script and nothing in the corpus distinguishes them.
			return lang, 0.85
		}
	}
	if counts["latin"]*2 <= letters {
		return "", 0
	}
	return latinLanguage(text)
}

// Stopwords, by language. Function words rather than content words: they are the part
// of a language that does not change with the subject, which is what makes a short
// list work on a two-line message.
var stopwords = map[string][]string{
	"english":    {"the", "and", "you", "for", "that", "with", "this", "your", "have", "from", "not", "are", "was", "will", "would", "please", "our", "has", "been", "they"},
	"spanish":    {"que", "los", "las", "una", "por", "con", "para", "del", "como", "más", "este", "esta", "pero", "son", "sus", "todo", "puede", "usted", "sobre", "hasta"},
	"french":     {"les", "des", "que", "pour", "dans", "une", "sur", "avec", "pas", "vous", "nous", "est", "sont", "plus", "cette", "être", "votre", "mais", "aux", "par"},
	"german":     {"der", "die", "das", "und", "ist", "nicht", "sie", "mit", "für", "auf", "von", "dem", "den", "eine", "einen", "auch", "wird", "sich", "haben", "werden"},
	"italian":    {"che", "per", "non", "con", "una", "sono", "come", "del", "della", "nel", "alla", "più", "anche", "questo", "essere", "loro", "suo", "dalla", "negli", "gli"},
	"portuguese": {"que", "não", "com", "uma", "para", "por", "como", "mais", "dos", "das", "seu", "sua", "pelo", "pela", "está", "são", "foi", "ser", "nos", "isso"},
	"dutch":      {"het", "een", "van", "niet", "dat", "zijn", "met", "voor", "aan", "deze", "wordt", "worden", "maar", "door", "ook", "naar", "bij", "heeft", "kan", "als"},
	"polish":     {"nie", "jest", "się", "tego", "który", "jako", "przez", "przy", "oraz", "tylko", "jeszcze", "można", "aby", "lub", "bardzo", "wszystko", "gdzie", "temu", "jego", "już"},
	"swedish":    {"och", "att", "det", "som", "för", "med", "inte", "har", "den", "till", "kan", "från", "vara", "detta", "eller", "man", "när", "över", "sina", "vid"},
	"danish":     {"til", "det", "som", "med", "har", "ikke", "for", "der", "kan", "men", "din", "vil", "være", "denne", "eller", "ved", "efter", "alle", "skal", "bliver"},
	"norwegian":  {"til", "det", "som", "med", "har", "ikke", "for", "kan", "men", "din", "vil", "være", "denne", "eller", "ved", "etter", "alle", "skal", "blir", "sine"},
	"finnish":    {"että", "olla", "joka", "kuin", "sekä", "ovat", "myös", "kun", "voi", "tai", "niin", "mutta", "vain", "jos", "hän", "tämä", "ole", "sen", "nyt", "yli"},
	"turkish":    {"bir", "için", "daha", "gibi", "kadar", "sonra", "olarak", "değil", "veya", "ancak", "ile", "bu", "şu", "çok", "her", "olan", "üzere", "bize", "size", "var"},
	"romanian":   {"este", "care", "pentru", "sunt", "din", "care", "mai", "unei", "unui", "său", "său", "dacă", "după", "către", "prin", "fost", "avea", "face", "dar", "fără"},
	"czech":      {"který", "jako", "nebo", "když", "také", "ale", "jsou", "být", "této", "před", "více", "pouze", "však", "podle", "tak", "již", "své", "může", "aby", "kde"},
	"hungarian":  {"hogy", "nem", "egy", "meg", "volt", "csak", "még", "mint", "már", "vagy", "után", "ami", "ahol", "lehet", "kell", "amely", "ezek", "való", "ként", "nagy"},
	"indonesian": {"yang", "dan", "untuk", "dengan", "dari", "ini", "itu", "pada", "tidak", "akan", "adalah", "dalam", "oleh", "atau", "juga", "telah", "dapat", "sudah", "bisa", "harus"},
	"vietnamese": {"của", "và", "các", "cho", "không", "được", "trong", "người", "một", "những", "với", "này", "đã", "khi", "để", "có", "là", "như", "từ", "thì"},
}

func latinLanguage(text string) (string, float64) {
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r)
	})
	if len(words) < 3 {
		// Too little to tell. Unknown rather than a guess: a rule reading
		// `.language == "english"` on a two-word body should report indeterminate,
		// not be told the body is English because most mail is.
		return "", 0
	}
	present := map[string]bool{}
	for _, w := range words {
		present[w] = true
	}

	type score struct {
		lang string
		n    float64
	}
	var scores []score
	for lang, list := range stopwords {
		hits := 0
		for _, w := range list {
			if present[w] {
				hits++
			}
		}
		if hits > 0 {
			scores = append(scores, score{lang, float64(hits) / float64(len(list))})
		}
	}
	if len(scores) == 0 {
		return "", 0
	}
	sort.Slice(scores, func(i, j int) bool {
		if scores[i].n != scores[j].n {
			return scores[i].n > scores[j].n
		}
		return scores[i].lang < scores[j].lang
	})

	best := scores[0]
	runner := 0.0
	if len(scores) > 1 {
		runner = scores[1].n
	}
	// Confidence is the margin, not the raw hit rate. Danish and Norwegian share most
	// of these words, and a message that scores 0.5 on both has not been identified.
	conf := best.n - runner
	if conf <= 0.05 {
		return "", 0
	}
	if conf > 1 {
		conf = 1
	}
	return best.lang, conf
}
