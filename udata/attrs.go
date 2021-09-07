package udata

type Attr interface {
	xxx_IsNFTUDataAttr()
}

type Comment string

func (Comment) xxx_IsNFTUDataAttr() {}

type UnknownAttr []byte

func (UnknownAttr) xxx_IsNFTUDataAttr() {}
