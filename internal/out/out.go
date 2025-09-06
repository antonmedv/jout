package out

import (
	"encoding/json"
	"fmt"
)

func JSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(b))
}
