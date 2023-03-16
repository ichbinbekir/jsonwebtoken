package jsonwebtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

func Sign(payloadObject map[string]any, secret string) (string, error) {
	headerObject := map[string]any{"alg": "HS256"}
	headerBuffer, err := json.Marshal(headerObject)
	if err != nil {
		return "", err
	}
	headerBase64 := strings.Trim(base64.StdEncoding.EncodeToString(headerBuffer), "=")

	payloadyBuffer, err := json.Marshal(payloadObject)
	if err != nil {
		return "", err
	}
	bodyBase64 := strings.Trim(base64.StdEncoding.EncodeToString(payloadyBuffer), "=")

	up := headerBase64 + "." + bodyBase64

	hash := hmac.New(sha256.New, []byte(secret))
	hash.Write([]byte(up))
	hashBuffer := hash.Sum(nil)

	plusToken := strings.Trim(up+"."+base64.StdEncoding.EncodeToString(hashBuffer), "=")
	slahsToken := strings.ReplaceAll(plusToken, "+", "-")
	token := strings.ReplaceAll(slahsToken, "/", "_")

	return token, nil
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