/*
	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at
		http://www.apache.org/licenses/LICENSE-2.0
	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/
package kek

import (
	"encoding/hex"
	"strings"
	"testing"
)

// --- 3DES tests ---

func TestAddComponentInvalidValue(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C", TripleDES)

	err := kek.AddComponent(1, "invalid", "DD1376")
	if err == nil {
		t.Fatal("should have failed if the component value is invalid")
	}
}

func TestAddComponentCheckValueNotTally(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C", TripleDES)

	err := kek.AddComponent(1, "E38FD6D9EF85A892F2FBFDD083A407AE", "DD1376")
	if err == nil {
		t.Fatal("should have failed if the component check value does not tally")
	}
}

func TestAddComponentSuccess(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C", TripleDES)

	err := kek.AddComponent(1, "E38FD6D9EF85A892F2FBFDD083A407AE", "DD1375")
	if err != nil {
		t.Fatalf("adding component failed with %v", err)
	}
}

func TestIsComplete(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C", TripleDES)
	if kek.IsComplete() {
		t.Fatal("isComplete should report false after 0/3 components have been added")
	}

	kek.AddComponent(1, "E38FD6D9EF85A892F2FBFDD083A407AE", "DD1375")
	if kek.IsComplete() {
		t.Fatal("isComplete should report false after 1/3 components have been added")
	}

	kek.AddComponent(2, "D0085DBFFB3723B926CB7980B9EA6268", "DACAF5")
	if kek.IsComplete() {
		t.Fatal("isComplete should report false after 2/3 components have been added")
	}

	kek.AddComponent(3, "20295EBC0B80BF5EF7F78C9125686D3B", "DE5AA9")
	if !kek.IsComplete() {
		t.Fatal("isComplete should report true after 3/3 components have been added")
	}
}

func TestMergeResultKeyCheckValueDoesNotTally(t *testing.T) {
	kek := New("visa", 1, 3, "123AB", TripleDES)

	err := kek.AddComponent(1, "E38FD6D9EF85A892F2FBFDD083A407AE", "DD1375")
	if err != nil {
		t.Fatalf("adding component 1 failed with %v", err)
	}

	err = kek.AddComponent(2, "D0085DBFFB3723B926CB7980B9EA6268", "DACAF5")
	if err != nil {
		t.Fatalf("adding component 2 failed with %v", err)
	}

	err = kek.AddComponent(3, "20295EBC0B80BF5EF7F78C9125686D3B", "DE5AA9")
	if err != nil {
		t.Fatalf("adding component 3 failed with %v", err)
	}

	_, err = kek.Merge()
	if err == nil {
		t.Fatal("should have failed if the result key check value does not tally")
	}
}

func TestMergeResultKeySuccess(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C", TripleDES)

	err := kek.AddComponent(1, "E38FD6D9EF85A892F2FBFDD083A407AE", "DD1375")
	if err != nil {
		t.Fatalf("adding component 1 failed with %v", err)
	}

	err = kek.AddComponent(2, "D0085DBFFB3723B926CB7980B9EA6268", "DACAF5")
	if err != nil {
		t.Fatalf("adding component 2 failed with %v", err)
	}

	err = kek.AddComponent(3, "20295EBC0B80BF5EF7F78C9125686D3B", "DE5AA9")
	if err != nil {
		t.Fatalf("adding component 3 failed with %v", err)
	}

	resultKey, err := kek.Merge()
	if err != nil {
		t.Fatalf("merge result key failed with %v", err)
	}
	expectedKey := "13AED5DA1F32347523C708C11F2608FD13AED5DA1F323475"
	if !strings.EqualFold(expectedKey, hex.EncodeToString(resultKey.GetKeyBytes())) {
		t.Fatalf("Expected %s but got back %s", expectedKey, hex.EncodeToString(resultKey.GetKeyBytes()))
	}
}

// --- AES ECB KCV tests ---

func TestAESECBAddComponentInvalidValue(t *testing.T) {
	kek := New("test", 1, 3, "4DDC67", AES_ECB)

	err := kek.AddComponent(1, "invalid", "40ED1B")
	if err == nil {
		t.Fatal("should have failed if the component value is invalid")
	}
}

func TestAESECBAddComponentCheckValueNotTally(t *testing.T) {
	kek := New("test", 1, 3, "4DDC67", AES_ECB)

	err := kek.AddComponent(1, "A1B2C3D4E5F60718293A4B5C6D7E8F90", "000000")
	if err == nil {
		t.Fatal("should have failed if the component check value does not tally")
	}
}

func TestAESECBAddComponentSuccess(t *testing.T) {
	kek := New("test", 1, 3, "4DDC67", AES_ECB)

	err := kek.AddComponent(1, "A1B2C3D4E5F60718293A4B5C6D7E8F90", "40ED1B")
	if err != nil {
		t.Fatalf("adding AES ECB component failed with %v", err)
	}
}

func TestAESECBMergeCheckValueDoesNotTally(t *testing.T) {
	kek := New("test", 1, 3, "000000", AES_ECB)

	kek.AddComponent(1, "A1B2C3D4E5F60718293A4B5C6D7E8F90", "40ED1B")
	kek.AddComponent(2, "11223344556677889900AABBCCDDEEFF", "DD566B")
	kek.AddComponent(3, "FEDCBA9876543210FEDCBA9876543210", "D0EAE1")

	_, err := kek.Merge()
	if err == nil {
		t.Fatal("should have failed if the result key check value does not tally")
	}
}

func TestAESECBMergeSuccess(t *testing.T) {
	kek := New("test", 1, 3, "4DDC67", AES_ECB)

	err := kek.AddComponent(1, "A1B2C3D4E5F60718293A4B5C6D7E8F90", "40ED1B")
	if err != nil {
		t.Fatalf("adding component 1 failed with %v", err)
	}

	err = kek.AddComponent(2, "11223344556677889900AABBCCDDEEFF", "DD566B")
	if err != nil {
		t.Fatalf("adding component 2 failed with %v", err)
	}

	err = kek.AddComponent(3, "FEDCBA9876543210FEDCBA9876543210", "D0EAE1")
	if err != nil {
		t.Fatalf("adding component 3 failed with %v", err)
	}

	resultKey, err := kek.Merge()
	if err != nil {
		t.Fatalf("AES ECB merge failed with %v", err)
	}
	expectedKey := "4E4C4A08C6C442804EE65B7FD7F7537F"
	if !strings.EqualFold(expectedKey, hex.EncodeToString(resultKey.GetKeyBytes())) {
		t.Fatalf("Expected %s but got back %s", expectedKey, hex.EncodeToString(resultKey.GetKeyBytes()))
	}
}

// --- AES CMAC KCV tests ---

func TestAESCMACAddComponentCheckValueNotTally(t *testing.T) {
	kek := New("test", 1, 3, "CB8700", AES_CMAC)

	err := kek.AddComponent(1, "A1B2C3D4E5F60718293A4B5C6D7E8F90", "000000")
	if err == nil {
		t.Fatal("should have failed if the CMAC component check value does not tally")
	}
}

func TestAESCMACAddComponentSuccess(t *testing.T) {
	kek := New("test", 1, 3, "CB8700", AES_CMAC)

	err := kek.AddComponent(1, "A1B2C3D4E5F60718293A4B5C6D7E8F90", "9AD77D")
	if err != nil {
		t.Fatalf("adding AES CMAC component failed with %v", err)
	}
}

func TestAESCMACMergeSuccess(t *testing.T) {
	kek := New("test", 1, 3, "CB8700", AES_CMAC)

	err := kek.AddComponent(1, "A1B2C3D4E5F60718293A4B5C6D7E8F90", "9AD77D")
	if err != nil {
		t.Fatalf("adding component 1 failed with %v", err)
	}

	err = kek.AddComponent(2, "11223344556677889900AABBCCDDEEFF", "894726")
	if err != nil {
		t.Fatalf("adding component 2 failed with %v", err)
	}

	err = kek.AddComponent(3, "FEDCBA9876543210FEDCBA9876543210", "CB53D6")
	if err != nil {
		t.Fatalf("adding component 3 failed with %v", err)
	}

	resultKey, err := kek.Merge()
	if err != nil {
		t.Fatalf("AES CMAC merge failed with %v", err)
	}
	expectedKey := "4E4C4A08C6C442804EE65B7FD7F7537F"
	if !strings.EqualFold(expectedKey, hex.EncodeToString(resultKey.GetKeyBytes())) {
		t.Fatalf("Expected %s but got back %s", expectedKey, hex.EncodeToString(resultKey.GetKeyBytes()))
	}
}

func TestAESCMACMergeCheckValueDoesNotTally(t *testing.T) {
	kek := New("test", 1, 3, "000000", AES_CMAC)

	kek.AddComponent(1, "A1B2C3D4E5F60718293A4B5C6D7E8F90", "9AD77D")
	kek.AddComponent(2, "11223344556677889900AABBCCDDEEFF", "894726")
	kek.AddComponent(3, "FEDCBA9876543210FEDCBA9876543210", "CB53D6")

	_, err := kek.Merge()
	if err == nil {
		t.Fatal("should have failed if the CMAC result key check value does not tally")
	}
}
