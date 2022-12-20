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
typedef struct MatchingRuleResult MatchingRuleResult;
typedef struct MatchingRuleIterator MatchingRuleIterator;

typedef enum ExpressionValueType {
	 ExpressionValueType_Unknown,
	 ExpressionValueType_String,
	 ExpressionValueType_Number,
	 ExpressionValueType_Integer,
	 ExpressionValueType_Decimal,
	 ExpressionValueType_Boolean,
 } ExpressionValueType;

// Initialise the core
void pactffi_init(char* log);
void pactffi_string_delete(char *string);

MatchingRuleDefinitionResult *pactffi_parse_matcher_definition(const char *expression);
const char *pactffi_matcher_definition_error(MatchingRuleDefinitionResult *definition);
struct MatchingRuleIterator *pactffi_matcher_definition_iter(const struct MatchingRuleDefinitionResult *definition);
void pactffi_matching_rule_iter_delete(struct MatchingRuleIterator *iter);
void pactffi_matcher_definition_delete(const struct MatchingRuleDefinitionResult *definition);

// Generators
Generator *pactffi_matcher_definition_generator(MatchingRuleDefinitionResult *definition);
const char *pactffi_generator_to_json(const struct Generator *generator);
const char *pactffi_generator_generate_string(const struct Generator *generator, const char *context_json);
unsigned short pactffi_generator_generate_integer(const struct Generator *generator, const char *context_json);
// TODO: get rust to make this opaque as well
struct StringResult pactffi_generate_datetime_string(const char *format);
struct StringResult pactffi_generate_regex_value(const char *regex);

// Matching Rules
const struct MatchingRuleResult *pactffi_matching_rule_iter_next(struct MatchingRuleIterator *iter);
const char* pactffi_matching_rule_to_json(const struct MatchingRule *rule);
const struct MatchingRule *pactffi_matching_rule_from_json(const char *rule);
const char* pactffi_matcher_definition_value(MatchingRuleDefinitionResult *definition);
ExpressionValueType pactffi_matcher_definition_value_type(const struct MatchingRuleDefinitionResult *definition);
const struct MatchingRule *pactffi_matching_rule_pointer(const struct MatchingRuleResult *rule_result);

// Check if a value satisfies a given matching rule
// (used on the verification side of an interaction)
const char *pactffi_matches_string_value(const struct MatchingRule *matching_rule, const char *expected_value, const char *actual_value, uint8_t cascaded);
const char *pactffi_matches_u64_value(const struct MatchingRule *matching_rule, uint64_t expected_value, uint64_t actual_value, uint8_t cascaded);
const char *pactffi_matches_i64_value(const struct MatchingRule *matching_rule, int64_t expected_value, int64_t actual_value, uint8_t cascaded);
const char *pactffi_matches_f64_value(const struct MatchingRule *matching_rule, double expected_value, double actual_value, uint8_t cascaded);
const char *pactffi_matches_bool_value(const struct MatchingRule *matching_rule, uint8_t expected_value, uint8_t actual_value, uint8_t cascaded);
const char *pactffi_matches_binary_value(const struct MatchingRule *matching_rule, const unsigned char *expected_value, uintptr_t expected_value_len, const unsigned char *actual_value, uintptr_t actual_value_len, uint8_t cascaded);
const char *pactffi_matches_json_value(const struct MatchingRule *matching_rule, const char *expected_value, const char *actual_value, uint8_t cascaded);
bool pactffi_check_regex(const char *regex, const char *example);

*/
import "C"
import (
	"encoding/json"
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

// TODO: rewrite this and wrap the types (e.g. type state pattern), so that you can only
//       call functions once a value is populated and accessible

func ParseMatcherDefinition(definition string) *C.MatchingRuleDefinitionResult {
	cDefinition := C.CString(definition)
	defer free(cDefinition)
	res := C.pactffi_parse_matcher_definition(cDefinition)

	return res
}

func MatcherDefinitionDelete(definition *C.MatchingRuleDefinitionResult) {
	C.pactffi_matcher_definition_delete(definition)
}

func MatchingRulePtr(matchingRuleResult *C.MatchingRuleResult) *C.MatchingRule {
	return C.pactffi_matching_rule_pointer(matchingRuleResult)
}

// Extract the matching rule value
// This will _always_ be a string. Use MatcherDefinitionValueType to cast to the correct type
func MatcherDefinitionValue(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) string {
	res := C.pactffi_matcher_definition_value(matchingRuleDefinitionResult)

	log.Println("[INFO] result", C.GoString(res))
	return C.GoString(res)
}

type ExpressionValueType uint

const (
	ExpressionValueTypeUnknown ExpressionValueType = 0
	ExpressionValueTypeString  ExpressionValueType = 1
	ExpressionValueTypeNumber  ExpressionValueType = 2
	ExpressionValueTypeInteger ExpressionValueType = 3
	ExpressionValueTypeDecimal ExpressionValueType = 4
	ExpressionValueTypeBoolean ExpressionValueType = 5
)

// Extract the matching rule value
func MatcherDefinitionValueType(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) ExpressionValueType {
	return ExpressionValueType(C.pactffi_matcher_definition_value_type(matchingRuleDefinitionResult))
}

func MatcherDefinitionGenerator(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) *C.Generator {
	return C.pactffi_matcher_definition_generator(matchingRuleDefinitionResult)
}

func MatchingRuleToJson(matchingRule *C.MatchingRule) (MatchingRule, error) {
	var rule MatchingRule
	res := C.pactffi_matching_rule_to_json(matchingRule)

	log.Println("[DEBUG] JSON matching rules: ", C.GoString(res))

	defer pactStringDelete(res)

	err := json.Unmarshal([]byte(C.GoString(res)), &rule)

	return rule, err
}

func MatchingRuleFromJson(rule string) *C.MatchingRule {
	cRule := C.CString(rule)
	defer free(cRule)

	return C.pactffi_matching_rule_from_json(cRule)
}

func MatcherDefinitionError(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) error {
	log.Println("[DEBUG] getMatchingRuleError")

	res := C.pactffi_matcher_definition_error(matchingRuleDefinitionResult)

	errors := strings.TrimSpace(C.GoString(res))

	if errors != "" {
		return fmt.Errorf("unable to parse matching rule definition: %s", errors)
	}

	return nil
}

func MatcherDefinitionIter(matchingRuleDefinitionResult *C.MatchingRuleDefinitionResult) *C.MatchingRuleIterator {
	log.Println("[DEBUG] getMatchingRuleIterator")

	return C.pactffi_matcher_definition_iter(matchingRuleDefinitionResult)
}

func MatcherDefinitionIterDelete(iter *C.MatchingRuleIterator) {
	C.pactffi_matching_rule_iter_delete(iter)
}

func MatchingRuleIterNext(matchingRuleIterator *C.MatchingRuleIterator) *C.MatchingRuleResult {
	log.Println("[DEBUG] getMatchingRuleResult")

	return C.pactffi_matching_rule_iter_next(matchingRuleIterator)
}

func GeneratorToJSON(g *C.Generator) (Generator, error) {
	res := C.pactffi_generator_to_json(g)
	var generator Generator

	log.Println("[DEBUG] JSON generated rules: ", C.GoString(res))

	defer pactStringDelete(res)

	err := json.Unmarshal([]byte(C.GoString(res)), &generator)

	return generator, err
}

func GeneratorGenerateString(generator *C.Generator, contextJSON string) string {
	cContext := C.CString(contextJSON)
	defer free(cContext)

	res := C.pactffi_generator_generate_string(generator, cContext)

	return C.GoString(res)
}
func GeneratorGenerateInteger(generator *C.Generator, contextJSON string) uint8 {
	cContext := C.CString(contextJSON)
	defer free(cContext)

	return uint8(C.pactffi_generator_generate_integer(generator, cContext))
}

// Check if a value satisfies a given matching rule
// (used on the verification side of an interaction)

func MatchesStringValue(rule *C.MatchingRule, expected string, actual string, cascaded bool) string {
	cExpected := C.CString(expected)
	cActual := C.CString(actual)
	defer free(cExpected)
	defer free(cActual)

	res := C.pactffi_matches_string_value(rule, cExpected, cActual, boolean(cascaded))

	return C.GoString(res)
}

func MatchesU64Value(rule *C.MatchingRule, expected uint64, actual uint64, cascaded bool) string {
	res := C.pactffi_matches_u64_value(rule, C.ulonglong(expected), C.ulonglong(actual), boolean(cascaded))

	return C.GoString(res)
}

func MatchesI64Value(rule *C.MatchingRule, expected int64, actual int64, cascaded bool) string {
	res := C.pactffi_matches_i64_value(rule, C.longlong(expected), C.longlong(actual), boolean(cascaded))

	return C.GoString(res)
}

func MatchesF64Value(rule *C.MatchingRule, expected float64, actual float64, cascaded bool) string {
	res := C.pactffi_matches_f64_value(rule, C.double(expected), C.double(actual), boolean(cascaded))

	return C.GoString(res)
}

func MatchesBoolValue(rule *C.MatchingRule, expected bool, actual bool, cascaded bool) string {
	res := C.pactffi_matches_bool_value(rule, boolean(expected), boolean(actual), boolean(cascaded))

	return C.GoString(res)
}

func MatchesBinaryValue(rule *C.MatchingRule, expected []byte, expectedValueLen uintptr, actual []byte, actualValueLen uintptr, cascaded bool) string {

	res := C.pactffi_matches_binary_value(rule, (*C.uchar)(unsafe.Pointer(&expected[0])), C.ulong(expectedValueLen), (*C.uchar)(unsafe.Pointer(&actual[0])), C.ulong(actualValueLen), boolean(cascaded))

	return C.GoString(res)
}

func MatchesJsonValue(rule *C.MatchingRule, expected string, actual string, cascaded bool) string {
	cExpected := C.CString(expected)
	cActual := C.CString(actual)
	defer free(cExpected)
	defer free(cActual)

	res := C.pactffi_matches_json_value(rule, cExpected, cActual, boolean(cascaded))

	return C.GoString(res)
}

func MatchesRegex(rule *C.MatchingRule, regex string, example string) bool {
	cRegex := C.CString(regex)
	cExample := C.CString(example)
	defer free(cRegex)
	defer free(cExample)

	res := C.pactffi_check_regex(cRegex, cExample)

	return int(res) != 0
}

func free(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func pactStringDelete(str *C.char) {
	C.pactffi_string_delete(str)
}

func boolean(val bool) C.uchar {
	if val {
		return C.uchar(1)

	}
	return C.uchar(0)
}
