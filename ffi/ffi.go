package ffi

/*
// Library headers
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
typedef int bool;
#define true 1
#define false 0


typedef struct MatchingRuleDefinitionResult MatchingRuleDefinitionResult;
typedef struct Generator Generator;
typedef struct MatchingRule MatchingRule;
typedef struct MatchingRuleIterator MatchingRuleIterator;

typedef enum MatchingRuleResult_Tag {
   // The matching rule from the expression.
	 MatchingRuleResult_MatchingRule,
	 // A reference to a named item.
	 MatchingRuleResult_MatchingReference,
 } MatchingRuleResult_Tag;

 typedef struct MatchingRuleResult_MatchingRule_Body {
	 uint16_t _0;
	 const char *_1;
	 const struct MatchingRule *_2;
 } MatchingRuleResult_MatchingRule_Body;

 typedef struct MatchingRuleResult {
	 MatchingRuleResult_Tag tag;
	 union {
		 MatchingRuleResult_MatchingRule_Body matching_rule;
		 struct {
			 const char *matching_reference;
		 };
	 } value;
 } MatchingRuleResult;

// Initialise the core
void pactffi_init(char* log);

MatchingRuleDefinitionResult* pactffi_parse_matcher_definition(const char *expression);
const char *pactffi_matcher_definition_error(MatchingRuleDefinitionResult *definition);
const char* pactffi_matcher_definition_value(MatchingRuleDefinitionResult *definition);
Generator* *pactffi_matcher_definition_generator(MatchingRuleDefinitionResult *definition);

// Get the iterator
struct MatchingRuleIterator *pactffi_matcher_definition_iter(const struct MatchingRuleDefinitionResult *definition);

// Get the next result
const struct MatchingRuleResult *pactffi_matching_rule_iter_next(struct MatchingRuleIterator *iter);

// Get the rule as JSON
const char* pactffi_matching_rule_to_json(const struct MatchingRule *rule);

// Ditto for Generators!



// segfault
// [pact_ffi/src/models/matching_rules.rs:19] "pactffi_matching_rule_to_json" = "pactffi_matching_rule_to_json"
// [pact_ffi/src/models/matching_rules.rs:22] &rule = SIGILL: illegal instruction
// "The SIGILL signal is raised when an attempt is made to execute an invalid, privileged,
// or ill-formed instruction. SIGILL is usually caused by a program error that overlays code with data
// or by a call to a function that is not linked into the program load module."

// [pact_ffi/src/models/expressions.rs:391] "pactffi_matching_rule_iter_next" = "pactffi_matching_rule_iter_next"
// [pact_ffi/src/models/expressions.rs:393] &result = MatchingRule(
//     2,
//     0x0000600000014010,
//     0x0000000208b75ac0,
// )
// res &{tag:0 _:[0 0 0 0] value:[2 0 183 8 2 0 0 0 16 64 1 0 0 96 0 0 192 90 183 8 2 0 0 0]}
// char: \w{3}\d+
// num: 2
// getMatchingRuleJSON
// [pact_ffi/src/models/matching_rules.rs:19] "pactffi_matching_rule_to_json" = "pactffi_matching_rule_to_json"
// [pact_ffi/src/models/matching_rules.rs:21] &rule = 0x0000000208b75ac0
// [pact_ffi/src/models/matching_rules.rs:23] &rule = SIGILL: illegal instruction
const struct MatchingRule *matching_rule_from_result(const struct MatchingRuleResult *result) {
	return result->value.matching_rule._2;
}

// Correct value
const char *matching_rule_char_from_result(const struct MatchingRuleResult *result) {
	return result->value.matching_rule._1;
}

// Correct value
uint16_t matching_rule_num_from_result(const struct MatchingRuleResult *result) {
	return result->value.matching_rule._0;
}

void get_matching_rule_json_from_expression(const char* expression) {
	MatchingRuleDefinitionResult* definition = pactffi_parse_matcher_definition(expression);

	// Get iterator
	struct MatchingRuleIterator* iterator = pactffi_matcher_definition_iter(definition);

	// Get the first matching result (ignoring error checking for brevity)
	const struct MatchingRuleResult* result = pactffi_matching_rule_iter_next(iterator);

	// Get the rule enum value (should match regex value of 2)
	printf("result->value.matching_rule._0 => %d \n", result->value.matching_rule._0);

	// Get the rule detail (in this case, the regx)
	printf("result->value.matching_rule._1 => %s \n", result->value.matching_rule._1);

	// Get the rule as JSON
	printf("calling pactffi_matching_rule_to_json \n");
	const char* json = pactffi_matching_rule_to_json(result->value.matching_rule._2);
	printf("JSON => %s \n", json);
}

*/
import "C"
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"unsafe"
	// "github.com/davecgh/go-spew/spew"
)

var once = sync.Once{}

func Init() {
	log.Println("[DEBUG] initialising native interface")

	once.Do(func() {
		// Log to file if specified
		pactLogLevel := os.Getenv("PACT_LOG_LEVEL")
		logLevel := os.Getenv("LOG_LEVEL")

		level := "INFO"
		if pactLogLevel != "" {
			level = pactLogLevel
		} else if logLevel != "" {
			level = logLevel
		}

		log.Println("[DEBUG] initialising FFI interface at log level", level)
		C.pactffi_init(C.CString(level))
	})
}

type MatchingRule map[string]interface{}

func ParseMatcherDefinition(definition string) *C.MatchingRuleDefinitionResult {
	cDefinition := C.CString(definition)
	defer free(cDefinition)
	res := C.pactffi_parse_matcher_definition(cDefinition)

	log.Println("[INFO] result", res)

	return res
}

// Extract the matching rule value
func ParseMatcherDefinitionValue(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) string {
	res := C.pactffi_matcher_definition_value(matchingRuleDefinitionResult)

	log.Println("[INFO] result", C.GoString(res))
	return C.GoString(res)
}

func ParseMatcherDefinitionMatchingRules(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) ([]MatchingRule, error) {
	// void get_matching_rule_json_from_expression(const char* expression) {
	C.get_matching_rule_json_from_expression(C.CString("matching(regex, '\\w{3}\\d+', 'abc123')"))
	// C.get_matching_rule_json_from_expression(C.CString("matching(type, 42)"))

	return nil, nil
}

// Extract the matching rule JSON
func ParseMatcherDefinitionMatchingRules2(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) ([]MatchingRule, error) {
	fmt.Println("ParseMatcherDefinitionMatchingRules")
	log.Println("[DEBUG] ParseMatcherDefinitionMatchingRules")

	err := getMatchingRuleError(matchingRuleDefinitionResult)
	rules := make([]MatchingRule, 0)

	if err != nil {
		return rules, err
	}

	iter := getMatchingRuleIterator(matchingRuleDefinitionResult)

	for {
		res := getMatchingRuleResult(iter)
		fmt.Printf("res %+v \n", res)
		log.Println("[DEBUG] res", res)

		if res == nil {
			fmt.Println("no more matching rule results")
			log.Println("[DEBUG] no more matching rule results")

			break
		}

		tag := res.tag

		// Determine: MatchingRuleResult_Tag
		// 0 => MatchingRuleResult_MatchingRule,
		// 1 => MatchingRuleResult_MatchingReference,

		if tag == 0 {
			log.Println("[DEBUG] discovered a matching rule")

			// rule_body := (*C.MatchingRuleResult_MatchingRule_Body)(unsafe.Pointer(&res))
			// rule_body := (*C.MatchingRuleResult_MatchingRule_Body)(unsafe.Pointer(&res.value))
			// rule_body := (*C.MatchingRuleResult_MatchingRule_Body)(unsafe.Pointer(&res.matching_rule))
			// rule_body := (*C.MatchingRuleResult_MatchingRule_Body)(unsafe.Pointer(&res))
			// rule_body := (*C.MatchingRuleResult_MatchingRule_Body)(unsafe.Pointer(&res.[0]))
			// matchingRule := MatchingRuleFromUnion(res)
			// Use C to test this
			// C.get_matching_rule_json_from_expression(C.CString("matching(type, 42)"))

			// matchingRule := C.matching_rule_from_result(res)
			// c := C.matching_rule_char_from_result(res)
			// fmt.Println("char:", C.GoString(c))
			// num := C.matching_rule_num_from_result(res)
			// fmt.Println("num:", num)
			// // matchingRule := union_to_matching_rule(res.value)
			// // matchingRule := getMatchingRuleJSONFromResult(res)
			// // spew.Dump(rule_body._2)
			// log.Println("[DEBUG] matching rule JSON:", matchingRule)

			// // TODO: this should be the correct path to the matching rule object
			// // json2 := getMatchingRuleJSON((rule_body._2))
			// // log.Println("[DEBUG] matching rule JSON", string(json2))

			// // TODO: Why is this in field 1????? did the pact.h cbingen get the alignment wrong or something?
			// // js := getMatchingRuleJSON(rule_body._2)
			// // js := getMatchingRuleJSON((*C.MatchingRule)(unsafe.Pointer(rule_body._2)))
			// // js := getMatchingRuleJSON(rule_body._2)
			// js := getMatchingRuleJSON(matchingRule)
			// log.Println("[DEBUG] matching rule JSON", js)
			// log.Println("[DEBUG] matching rule JSON", string(js))

			// var rule MatchingRule
			// err := json.Unmarshal([]byte(js), &rule)

			// if err != nil {
			// 	return rules, err
			// }

			// rules = append(rules, rule)

		} else {
			return rules, fmt.Errorf("plugin does not support matching references")
		}
	}

	return rules, nil
}

func getMatchingRuleError(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) error {
	fmt.Println("getMatchingRuleError")
	log.Println("[DEBUG] getMatchingRuleError")

	res := C.pactffi_matcher_definition_error(matchingRuleDefinitionResult)

	errors := strings.TrimSpace(C.GoString(res))

	if errors != "" {
		return fmt.Errorf("unable to parse matching rule definition: %s", errors)
	}

	return nil
}

func getMatchingRuleIterator(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) *C.MatchingRuleIterator {
	fmt.Println("getMatchingRuleIterator")
	log.Println("[DEBUG] getMatchingRuleIterator")

	return C.pactffi_matcher_definition_iter(matchingRuleDefinitionResult)
}

func getMatchingRuleResult(matchingRuleIterator *C.MatchingRuleIterator) *C.MatchingRuleResult {
	fmt.Println("getMatchingRuleResult")
	log.Println("[DEBUG] getMatchingRuleResult")

	return C.pactffi_matching_rule_iter_next(matchingRuleIterator)
}

// func getMatchingRuleJSONFromResult(result *C.MatchingRuleResult) string {
// 	fmt.Println("getMatchingRuleFromResult 2")
// 	log.Println("[DEBUG] getMatchingRuleFromResult 2")

// 	res := C.pactffi_matching_rule_json_from_result(result)

// 	return C.GoString(res)
// }

func getMatchingRuleJSON(matchingRule *C.MatchingRule) string {
	fmt.Println("getMatchingRuleJSON")
	log.Println("[DEBUG] getMatchingRuleJSON")

	res := C.pactffi_matching_rule_to_json(matchingRule)
	fmt.Println("res", res)

	return C.GoString(res)
}

func free(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func MatchingRuleFromUnion2(data C.MatchingRuleResult) *C.MatchingRule {
	var union [24]byte = data.value // The union, as 24 contiguous bytes of memory
	// Why 24? Go finds the biggest type in the union and allocates that space

	// The first magic. The address of the first element in that contiguous memory
	// is the address of that union.
	var addr *byte = &union[0]
	fmt.Println(addr)

	// The second magic. Instead of pointing to bytes of memory, we can point
	// to some useful type, T, by changing the type of the pointer to *T using
	// unsafe.Pointer. In this case we want to interpret the union as member
	// `MatchingRuleResult_MatchingRule_Body matching_rule`. That is, T = (*C.MatchingRuleResult_MatchingRule_Body) and *T = (**C.MatchingRuleResult_MatchingRule_Body).
	var cast **C.MatchingRuleResult_MatchingRule_Body = (**C.MatchingRuleResult_MatchingRule_Body)(unsafe.Pointer(addr))
	fmt.Println(cast)

	// The final step. We wanted the contents of the union, not the address
	// of the union. Dereference it!
	return (*cast)._2
}

func MatchingRuleFromUnion(data *C.MatchingRuleResult) *C.MatchingRule {
	star := (**C.MatchingRuleResult_MatchingRule_Body)(unsafe.Pointer(&data.value))
	return (**star)._2

}

// https://sunzenshen.github.io/tutorials/2015/05/09/cgotchas-intro.html
// https://stackoverflow.com/questions/14581063/golang-cgo-converting-union-field-to-go-type

func union_to_matching_rule(cbytes [24]byte) *C.MatchingRule {
	buf := bytes.NewBuffer(cbytes[:])
	var ptr uint64
	if err := binary.Read(buf, binary.LittleEndian, &ptr); err == nil {
		uptr := uintptr(ptr)
		var result *C.MatchingRuleResult_MatchingRule_Body = (*C.MatchingRuleResult_MatchingRule_Body)(unsafe.Pointer(uptr))
		fmt.Println("union_to_matching")
		fmt.Println(result)
		return result._2

	}
	return nil
}

// Options

// 1. c method in header to handle the union
// 2.
