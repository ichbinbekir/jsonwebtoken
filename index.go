package jsonwebtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

type Secret string

type Algorithm string

const (
	HS256 Algorithm = "HS256"
)

type SignOptions struct {
	Algorithm Algorithm
}

func Sign(payload map[string]any, secret string, options *SignOptions) (string, error) {
	headerObject := map[string]any{"alg": "HS256"}
	headerString, err := encode(headerObject)
	if err != nil {
		return "", err
	}

	payloadString, err := encode(payload)
	if err != nil {
		return "", err
	}

	up := headerString + "." + payloadString

	hash := hmac.New(sha256.New, []byte(secret))
	if _, err := hash.Write([]byte(up)); err != nil {
		return "", err
	}
	hashBuffer := hash.Sum(nil)

	plusToken := strings.Trim(up+"."+base64.StdEncoding.EncodeToString(hashBuffer), "=")
	slahsToken := strings.ReplaceAll(plusToken, "+", "-")
	token := strings.ReplaceAll(slahsToken, "/", "_")

	return token, nil
}

func encode(object map[string]any) (string, error) {
	buffer, err := json.Marshal(object)
	if err != nil {
		return "", err
	}
	base64 := strings.Trim(base64.StdEncoding.EncodeToString(buffer), "=")
	return base64, nil
}

func Verify(token string, secret string) error {
	tokenParts := strings.Split(token, ".")

	up := tokenParts[0] + "." + tokenParts[1]

	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(up))
	hashBuffer := hash.Sum(nil)

	plusSignature := strings.Trim(base64.StdEncoding.EncodeToString(hashBuffer), "=")
	slahsSignature := strings.ReplaceAll(plusSignature, "+", "-")
	signature := strings.ReplaceAll(slahsSignature, "/", "_")

	if tokenParts[2] == signature {
		return nil
	}
	return errors.New("signature not valid")
}

func Decode(token string) (map[string]any, error) {
	tokenParts := strings.Split(token, ".")

	buffer, err := base64.StdEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, err
	}

	var payload map[string]any
	json.Unmarshal(buffer, &payload)

	return payload, nil
}
