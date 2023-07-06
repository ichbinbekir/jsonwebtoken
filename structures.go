package jsonwebtoken

type Secret any //string | Buffer | KeyObject

type Algorithm string

const (
	HS256 Algorithm = "HS256"
	HS384 Algorithm = "HS384"
	HS512 Algorithm = "HS512"

	RS256 Algorithm = "RS256"
	RS384 Algorithm = "RS384"
	RS512 Algorithm = "RS512"

	ES256 Algorithm = "ES256"
	ES384 Algorithm = "ES384"
	ES512 Algorithm = "ES512"

	PS256 Algorithm = "PS256"
	PS384 Algorithm = "PS384"
	PS512 Algorithm = "PS512"
)

type DecodeOptions struct {
	Complete bool
	Json     bool
}

type VerifyOptions struct {
	Algorithms                     []Algorithm
	Audience                       any //string | RegExp | Array<string | RegExp> |
	ClockTimestamp                 int
	ClockTolerance                 int
	Complete                       bool
	Issuer                         any //string | string[]
	IgnoreExpiration               bool
	IgnoreNotBefore                bool
	Jwtid                          bool
	Nonce                          string
	Subject                        string
	MaxAge                         any //string | number
	AllowInvalidAsymmetricKeyTypes bool
}

type Jwt struct {
	Header    JwtHeader
	Payload   any //JwtPayload | string
	Signature string
}

type JwtPayload struct {
	/*[key: string]: any;
	  iss?: string | undefined;
	  sub?: string | undefined;
	  aud?: string | string[] | undefined;
	  exp?: number | undefined;
	  nbf?: number | undefined;
	  iat?: number | undefined;
	  jti?: string | undefined;*/
}

type SignOptions struct {
	Algorithm                      Algorithm
	Keyid                          string
	ExpiresIn                      any //string | number
	NotBefore                      any //string | number
	Audience                       any //string | string[]
	Subject                        string
	Issuer                         string
	Jwtid                          string
	MutatePayload                  bool
	NoTimestamp                    bool
	Header                         JwtHeader
	Encoding                       string
	AllowInsecureKeySizes          bool
	AllowInvalidAsymmetricKeyTypes bool
}

type JwtHeader struct {
	Alg  any    `json:"alg"` //string | Algorithm
	Typ  string `json:"typ,omitempty"`
	Cty  string `json:"cty,omitempty"`
	Crit any    `json:"crit,omitempty"` //Array<string | Exclude<keyof JwtHeader, 'crit'>>
	Kid  string `json:"kid,omitempty"`
	Jku  string `json:"jku,omitempty"`
	X5u  any    `json:"x5u,omitempty"` //string | string[]
	//x5t#S256 string
	X5t string `json:"x5t,omitempty"`
	X5c any    `json:"x5c,omitempty"` //string | string[]
}
