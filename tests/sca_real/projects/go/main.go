package main

import (
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/text/language"
)

func main() {
	fmt.Println(uuid.NewString(), language.English)
}
