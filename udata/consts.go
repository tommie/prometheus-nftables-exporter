package udata

type AttrType byte

const (
	TableComment AttrType = iota
)

const (
	ChainComment AttrType = iota
)

const (
	RuleComment AttrType = iota
	EBTablesPolicy
)

const (
	ObjComment AttrType = iota
)

const (
	SetKeyByteOrder AttrType = iota
	SetDataByteOrder
	SetMergeElements
	SetKeyTypeOf
	SetDataTypeOf
	SetExpr
	SetDataInterval
	SetComment
)

const (
	SetTypeOfExpr AttrType = iota
	SetTypeOfData
)

const (
	SetElemComment AttrType = iota
	SetElemFlags
)

type SetElemFlag byte

const (
	SetElemIntervalOpen SetElemFlag = 0x01
)
