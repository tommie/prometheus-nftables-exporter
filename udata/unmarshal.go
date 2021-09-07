// Package udata contains utilities to manipulate NFTables' user data fields.
//
// See https://git.netfilter.org/libnftnl/tree/include/udata.h and
// https://git.netfilter.org/libnftnl/tree/include/libnftnl/udata.h.
package udata

import (
	"fmt"
)

// An Unmarshaller can split udata into a stream of attributes.
type Unmarshaller struct {
	tail []byte

	err error
	typ AttrType
	tok []byte
}

// NewUnmarshaller creates a new unmarshaller, reading the given bytes.
func NewUnmarshaller(bs []byte) *Unmarshaller {
	return &Unmarshaller{tail: bs}
}

// Err returns the last error found while parsing the data.
func (p *Unmarshaller) Err() error {
	return p.err
}

// Next is called to make Type and Bytes point to the next
// attribute. Call repeated until false, and then check Err.
func (p *Unmarshaller) Next() bool {
	if p.err != nil {
		return false
	}

	if len(p.tail) < 2 {
		if len(p.tail) > 0 {
			p.err = fmt.Errorf("incomplete udata attribute header: %d bytes", len(p.tail))
		}
		return false
	}

	t := p.tail[0]
	l := int(p.tail[1])

	if len(p.tail) < 2+l {
		p.err = fmt.Errorf("incomplete udata attribute: got %d bytes, want %d bytes", len(p.tail), l)
		return false
	}

	p.typ = AttrType(t)
	p.tok = p.tail[2 : 2+l]
	p.tail = p.tail[2+l:]

	return true
}

// Type returns the attribute type of the current attribute.
func (p *Unmarshaller) Type() AttrType {
	if p.err != nil {
		return 0
	}

	return p.typ
}

// Bytes returns the body of the current attribute.
func (p *Unmarshaller) Bytes() []byte {
	if p.err != nil {
		return nil
	}

	return p.tok
}

// Unmarshal parses a sequence of attributes, using the given
// attribute unmarshaller for each one.
func Unmarshal(bs []byte, f AttrUnmarshalFunc) ([]Attr, error) {
	p := NewUnmarshaller(bs)

	var as []Attr
	for p.Next() {
		a, err := f(p.Type(), p.Bytes())
		if err != nil {
			return as, err
		}
		as = append(as, a)
	}

	return as, p.Err()
}

// An AttrUnmarshalFunc takes encoded attribute data and turns it into
// an Attr.
type AttrUnmarshalFunc func(AttrType, []byte) (Attr, error)

// UnmarshalTableAttr can read a user data attribute coming from a table.
func UnmarshalTableAttr(t AttrType, bs []byte) (Attr, error) {
	switch t {
	case TableComment:
		return unmarshalCommentAttr(bs)
	default:
		return UnknownAttr(bs), nil
	}
}

// UnmarshalChainAttr can read a user data attribute coming from a chain.
func UnmarshalChainAttr(t AttrType, bs []byte) (Attr, error) {
	switch t {
	case ChainComment:
		return unmarshalCommentAttr(bs)
	default:
		return UnknownAttr(bs), nil
	}
}

// UnmarshalRuleAttr can read a user data attribute coming from a rule.
func UnmarshalRuleAttr(t AttrType, bs []byte) (Attr, error) {
	switch t {
	case RuleComment:
		return unmarshalCommentAttr(bs)
	default:
		return UnknownAttr(bs), nil
	}
}

func unmarshalCommentAttr(bs []byte) (Attr, error) {
	if len(bs) == 0 || bs[len(bs)-1] != 0 {
		return nil, fmt.Errorf("incomplete string data")
	}
	return Comment(bs[:len(bs)-1]), nil
}
