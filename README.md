# JsonWebToken

## ⚡️ Quickstart

```go
package main

import "github.com/ichbinbekir/jsonwebtoken"

func main() {

  //Sign
  token, err := jsonwebtoken.Sign(map[string]any{"hello": "hello"}, "secret")
	if err != nil {
		panic(err)
	}
  fmt.Println(token)
  
  //Verify
  if err := jsonwebtoken.Verify(token, "secret"); err != nil {
		fmt.Println("Not Verify")
	}
  
  //Decode
  payload, err := jsonwebtoken.Decode(token)
	if err != nil {
		panic(err)
	}
  fmt.Println(payload)
  
}
```
