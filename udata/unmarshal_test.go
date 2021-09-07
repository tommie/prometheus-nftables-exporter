package udata

import (
	"fmt"
	"reflect"
	"testing"
)

func ExampleUnmarshaller() {
	um := NewUnmarshaller([]byte{1, 3, 'o', 'n', 'e', 2, 3, 't', 'w', 'o'})
	for um.Next() {
		fmt.Println(um.Type(), string(um.Bytes()))
	}
	if err := um.Err(); err != nil {
		fmt.Println(err)
	}
	// Output:
	// 1 one
	// 2 two
}

func TestUnmarshal(t *testing.T) {
	rawAttr := func(t AttrType, bs []byte) (Attr, error) {
		return UnknownAttr(append([]byte{byte(t)}, bs...)), nil
	}
	t.Run("empty", func(t *testing.T) {
		got, err := Unmarshal([]byte{}, rawAttr)
		if err != nil {
			t.Fatalf("failed: %v", err)
		}

		want := []Attr(nil)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("one", func(t *testing.T) {
		got, err := Unmarshal([]byte{1, 3, 'o', 'n', 'e'}, rawAttr)
		if err != nil {
			t.Fatalf("failed: %v", err)
		}

		want := []Attr{UnknownAttr{1, 'o', 'n', 'e'}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("two", func(t *testing.T) {
		got, err := Unmarshal([]byte{1, 3, 'o', 'n', 'e', 2, 3, 't', 'w', 'o'}, rawAttr)
		if err != nil {
			t.Fatalf("failed: %v", err)
		}

		want := []Attr{
			UnknownAttr{1, 'o', 'n', 'e'},
			UnknownAttr{2, 't', 'w', 'o'},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})

	t.Run("incomplete", func(t *testing.T) {
		_, err := Unmarshal([]byte{1}, rawAttr)
		if err == nil {
			t.Fatalf("succeeded when it shouldn't")
		}
	})

	t.Run("short", func(t *testing.T) {
		_, err := Unmarshal([]byte{1, 2, 'o'}, rawAttr)
		if err == nil {
			t.Fatalf("succeeded when it shouldn't")
		}
	})
}

func TestUnmarshalTableAttr(t *testing.T) {
	t.Run("comment", func(t *testing.T) {
		got, err := UnmarshalTableAttr(TableComment, []byte{'a', 'b', 'c', 0})
		if err != nil {
			t.Fatalf("failed: %v", err)
		}

		want := Comment("abc")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
}

func TestUnmarshalChainAttr(t *testing.T) {
	t.Run("comment", func(t *testing.T) {
		got, err := UnmarshalChainAttr(ChainComment, []byte{'a', 'b', 'c', 0})
		if err != nil {
			t.Fatalf("failed: %v", err)
		}

		want := Comment("abc")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
}

func TestUnmarshalRuleAttr(t *testing.T) {
	t.Run("comment", func(t *testing.T) {
		got, err := UnmarshalRuleAttr(RuleComment, []byte{'a', 'b', 'c', 0})
		if err != nil {
			t.Fatalf("failed: %v", err)
		}

		want := Comment("abc")
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}
	})
}
