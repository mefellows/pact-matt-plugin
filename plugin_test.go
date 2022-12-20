package main

import (
	"log"
	"testing"
)

func TestParseExpression(t *testing.T) {
	a, b, c, d := parseExpression("aeou")
	log.Println(a, b, c, d)
}
