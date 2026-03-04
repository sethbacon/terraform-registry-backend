package admin

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// getUserIDFromContext
// ---------------------------------------------------------------------------

func ginCtxWith(key string, val interface{}) *gin.Context {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	if key != "" {
		c.Set(key, val)
	}
	return c
}

func TestGetUserIDFromContext_Missing(t *testing.T) {
	c := ginCtxWith("", nil)
	_, ok := getUserIDFromContext(c)
	if ok {
		t.Error("expected false when user_id not in context")
	}
}

func TestGetUserIDFromContext_UUIDValue(t *testing.T) {
	id := uuid.New()
	c := ginCtxWith("user_id", id)
	got, ok := getUserIDFromContext(c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got != id {
		t.Errorf("got %v, want %v", got, id)
	}
}

func TestGetUserIDFromContext_StringValue(t *testing.T) {
	id := uuid.New()
	c := ginCtxWith("user_id", id.String())
	got, ok := getUserIDFromContext(c)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got != id {
		t.Errorf("got %v, want %v", got, id)
	}
}

func TestGetUserIDFromContext_InvalidString(t *testing.T) {
	c := ginCtxWith("user_id", "not-a-uuid")
	_, ok := getUserIDFromContext(c)
	if ok {
		t.Error("expected false for invalid UUID string")
	}
}

func TestGetUserIDFromContext_WrongType(t *testing.T) {
	c := ginCtxWith("user_id", 42) // int, not uuid or string
	_, ok := getUserIDFromContext(c)
	if ok {
		t.Error("expected false for wrong type")
	}
}

// ---------------------------------------------------------------------------
// splitString
// ---------------------------------------------------------------------------

func TestSplitString_Empty(t *testing.T) {
	result := splitString("", ",")
	if len(result) != 0 {
		t.Errorf("expected empty slice, got %v", result)
	}
}

func TestSplitString_SingleItem(t *testing.T) {
	result := splitString("hello", ",")
	if len(result) != 1 || result[0] != "hello" {
		t.Errorf("expected [hello], got %v", result)
	}
}

func TestSplitString_MultipleItems(t *testing.T) {
	result := splitString("a,b,c", ",")
	if len(result) != 3 || result[0] != "a" || result[1] != "b" || result[2] != "c" {
		t.Errorf("expected [a b c], got %v", result)
	}
}

func TestSplitString_TrailingSeparator(t *testing.T) {
	result := splitString("a,b,", ",")
	if len(result) != 2 || result[0] != "a" || result[1] != "b" {
		t.Errorf("expected [a b], got %v", result)
	}
}

func TestSplitString_ConsecutiveSeparators(t *testing.T) {
	result := splitString("a,,b", ",")
	// empty segments are skipped
	if len(result) != 2 || result[0] != "a" || result[1] != "b" {
		t.Errorf("expected [a b], got %v", result)
	}
}
