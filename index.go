package jsonwebtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
)

func Sign(payload any /* string | Buffer | object */, secretOrPrivateKey Secret, options SignOptions) (string, error) {
	options.Header.Alg = options.Algorithm

	headerBase64, err := base64Encode(options.Header)
	if err != nil {
		return "", err
	}

	payloadBase64, err := base64Encode(payload)
	if err != nil {
		return "", err
	}

	up := headerBase64 + "." + payloadBase64

	var hashBuffer []byte

	switch options.Algorithm {
	case HS256:
		hashBuffer, err = hmacEncode(sha256.New, secretOrPrivateKey, up)
	case HS384:
		hashBuffer, err = hmacEncode(sha512.New384, secretOrPrivateKey, up)
	case HS512:
		hashBuffer, err = hmacEncode(sha512.New, secretOrPrivateKey, up)
	}

	if err != nil {
		return "", err
	}

	return up + "." + base64.RawURLEncoding.EncodeToString(hashBuffer), nil
}

func base64Encode(data any) (string, error) {
	buffer, err := json.Marshal(data)
	return base64.RawURLEncoding.EncodeToString(buffer), err
}

func hmacEncode(h func() hash.Hash, secret any, token string) ([]byte, error) {
	var qweqwe []byte

	switch secret.(type) {
	case string:
		qweqwe = []byte(secret.(string))
	case []byte:
		qweqwe = secret.([]byte)
	}

	asd := hmac.New(h, qweqwe)
	if _, err := asd.Write([]byte(token)); err != nil {
		return []byte(""), err
	}

	return asd.Sum(nil), nil
}

func Verify(token string, secretOrPublicKey Secret, options VerifyOptions) (any, error) {
	parts := strings.Split(token, ".")

	up := parts[0] + "." + parts[1]

	headerBuffer, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}

	var header JwtHeader
	if json.Unmarshal(headerBuffer, &header) != nil {
		return nil, err
	}

	var hashBuffer []byte

	switch header.Alg {
	case "HS256":
		hashBuffer, err = hmacEncode(sha256.New, secretOrPublicKey, up)
		fmt.Println(header)
	case "HS384":
		hashBuffer, err = hmacEncode(sha512.New384, secretOrPublicKey, up)
	case "HS512":
		hashBuffer, err = hmacEncode(sha512.New, secretOrPublicKey, up)
	}

	if err != nil {
		return nil, err
	}

	if parts[2] != base64.RawURLEncoding.EncodeToString(hashBuffer) {
		return nil, errors.New("signature not valid")
	}

	return token, nil
} //Jwt | JwtPayload | string

func Decode(token string, options DecodeOptions) (any, error) {
	parts := strings.Split(token, ".")

	payloadBuffer, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var payload any
	if json.Unmarshal(payloadBuffer, &payload) != nil {
		return nil, err
	}

	return payload, nil
} //JwtPayload | string
