package des

import (
	"testing"
)

func TestInvalidDESKeys(t *testing.T) {
	invalidDESKeys := []string{
		"",
		"sme",
		"844e5fb5-96d1-4b19-9ce0-b90f252ea370",
		"8AC325EAE53E1C2X",
		"        naksn",
		"8AC325EAE53E1 C2X",
		"1C7EB5",
	}

	for _, desKey := range invalidDESKeys {
		if _, err := CreateFromDESKeyString(desKey); err == nil {
			t.Errorf("Expecting DES %s to be invalid", desKey)
		}
	}
}

func TestValidDESKeys(t *testing.T) {
	validDESKeys := []string{
		"0091CFE3ACFA3EAF",
		"812BF1D20A4EAE1D",
		"2C45FA08A4CC2C85",
	}

	for _, desKey := range validDESKeys {
		if _, err := CreateFromDESKeyString(desKey); err != nil {
			t.Errorf("Expecting DES %s to be valid", desKey)
		}
	}
}

func TestInvalidTripleDESKeys(t *testing.T) {
	invalidDESKeys := []string{
		"",
		"sme",
		"844e5fb5-96d1-4b19-9ce0-b90f252ea370",
		"        naksn",
		"2C45FA08A4CC2C85",
		"0091CFE3ACFA3EAF0091CFE3ACF",
	}

	for _, desKey := range invalidDESKeys {
		if _, err := CreateFromTripleDESKeyString(desKey); err == nil {
			t.Errorf("Expecting 3DES %s to be invalid", desKey)
		}
	}
}

func TestValidTripleDESKeys(t *testing.T) {
	validDESKeys := []string{
		"0091CFE3ACFA3EAF0091CFE3ACFA3EAF",
		"812BF1D20A4EAE1D812BF1D20A4EAE1D",
		"2C45FA08A4CC2C852C45FA08A4CC2C85",
	}

	for _, desKey := range validDESKeys {
		if _, err := CreateFromTripleDESKeyString(desKey); err != nil {
			t.Errorf("Expecting 3DES %s to be valid", desKey)
		}
	}
}
