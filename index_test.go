package jsonwebtoken

import (
	"testing"
)

func TestSign(t *testing.T) {
	token, err := Sign(map[string]any{"test": "test"}, "test", &SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Log(token)
	if token != "eyJhbGciOiJIUzI1NiJ9.eyJ0ZXN0IjoidGVzdCJ9.KOobRHDYyaesV_doOk11XXGKSONwzllraAaqqM4VFE4" {
		t.Fatal("token not valid")
	}
}

func TestVerify(t *testing.T) {
	token, err := Sign(map[string]any{"test": "test"}, "test", &SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(token, "test"); err != nil {
		t.Fatal(err)
	}
	if err := Verify(token, "asd"); err == nil {
		t.Fatal(err)
	}
}

func TestDecode(t *testing.T) {
	token, err := Sign(map[string]any{"asd": "test"}, "test", &SignOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if payload["asd"] != "test" {
		t.Fatal("payload not valid")
	}
}
