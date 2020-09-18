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

func TestAddComponentInvalidValue(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C")

	err := kek.AddComponent(1, "invalid", "DD1376")
	if err == nil {
		t.Fatal("should have failed if the component value is invalid")
	}
}

func TestAddComponentCheckValueNotTally(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C")

	err := kek.AddComponent(1, "E38FD6D9EF85A892F2FBFDD083A407AE", "DD1376")
	if err == nil {
		t.Fatal("should have failed if the component check value does not tally")
	}
}

func TestAddComponentSuccess(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C")

	err := kek.AddComponent(1, "E38FD6D9EF85A892F2FBFDD083A407AE", "DD1375")
	if err != nil {
		t.Fatalf("adding component failed with %v", err)
	}
}

func TestIsComplete(t *testing.T) {
	kek := New("visa", 1, 3, "2D617C")
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
	kek := New("visa", 1, 3, "123AB")

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
	kek := New("visa", 1, 3, "2D617C")

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
	if !strings.EqualFold(expectedKey, hex.EncodeToString(resultKey.KeyBytes)) {
		t.Fatalf("Expected %s but got back %s", expectedKey, hex.EncodeToString(resultKey.KeyBytes))
	}
}
