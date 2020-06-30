package kek

import "testing"

func TestAddComponent(t *testing.T) {
	zmk := NewZMKComponents("visa", 1, 3, "123AB")

	if zmk == nil {
		t.Error("Expected non nil zmk component")
	}

	err := zmk.AddComponent(1, "E38FD6D9EF85A892F2FBFDD083A407AE", "DD1375")

	if err != nil {
		t.Errorf("Adding components failed with %v", err)
	}
}
