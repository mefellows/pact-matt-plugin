package ffi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseExpressions(t *testing.T) {

	// For all definitions, see https://github.com/pact-foundation/pact-plugins/blob/main/docs/matching-rule-definition-expressions.md
	t.Run("parses the basic matching rule expressions", func(t *testing.T) {
		tests := []struct {
			name                           string
			expression                     string
			wantMatcherDefinitionValueType ExpressionValueType
			wantMatcherDefinitionType      string
			wantExpressionValue            string
			wantGeneratedValue             string
			wantError                      bool
		}{
			{
				name:                           "matching - no expression (string)",
				expression:                     "foo",
				wantMatcherDefinitionValueType: ExpressionValueTypeString,
				wantExpressionValue:            "foo",
				wantError:                      false,
			},
			{
				name:                           "matching - no expression (number)",
				expression:                     "1",
				wantMatcherDefinitionValueType: ExpressionValueTypeString, // Note: all expressions are treated as strings (unless specified), even non-expressions
				wantExpressionValue:            "1",
				wantError:                      false,
			},
			{
				name:                           "matching - exact type expression (integer)",
				expression:                     "matching(equalTo, 1)",
				wantMatcherDefinitionValueType: ExpressionValueTypeInteger, // Note: all expressions are treated as strings (unless specified), even non-expressions
				wantExpressionValue:            "1",
				wantError:                      false,
			},
			{
				name:                           "matching - exact type expression (decimal)",
				expression:                     "matching(equalTo, 41.76)",
				wantMatcherDefinitionValueType: ExpressionValueTypeDecimal, // Note: all expressions are treated as strings (unless specified), even non-expressions
				wantExpressionValue:            "41.76",
				wantError:                      false,
			},
			{
				name:                           "matching - type",
				expression:                     "matching(type, 'foo')",
				wantMatcherDefinitionValueType: ExpressionValueTypeString,
				wantMatcherDefinitionType:      "type",
				wantExpressionValue:            "foo",
				wantError:                      false,
			},
			{
				name:                           "matching - timestamp",
				expression:                     "matching(datetime, 'yyyy-MM-dd', '2000-01-01')",
				wantMatcherDefinitionValueType: ExpressionValueTypeString,
				wantMatcherDefinitionType:      "timestamp",
				wantExpressionValue:            "2000-01-01",
				wantGeneratedValue:             time.Now().Format("2006-01-02"), // This may be a flaky test if impl. changes
				wantError:                      false,
			},
			{
				name:                           "matching - eachKey",
				expression:                     `eachKey(matching(regex, '\$(\.\w+)+', '$.test.one'))`,
				wantMatcherDefinitionValueType: ExpressionValueTypeUnknown,
				wantMatcherDefinitionType:      "eachKey",
				wantError:                      false,
			},
			{
				name:                           "matching - invalid matching rule",
				expression:                     "matching(datetime, 'yyyy-MM-dd', '2000-01-01)", // <- missing trailing "'"
				wantMatcherDefinitionValueType: ExpressionValueTypeString,
				wantError:                      true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := ParseMatcherDefinition(tt.expression)

				err := MatcherDefinitionError(result)
				if tt.wantError {
					assert.Error(t, err)
					return
				} else {
					assert.NoError(t, err)
				}

				if tt.wantExpressionValue != "" {
					val := MatcherDefinitionValue(result)
					assert.Equal(t, tt.wantExpressionValue, val)
				}

				valueType := MatcherDefinitionValueType(result)
				assert.Equal(t, tt.wantMatcherDefinitionValueType, valueType)

				iter := MatcherDefinitionIter(result)
				ruleResult := MatchingRuleIterNext(iter)

				if ruleResult != nil {
					rule := MatchingRulePtr(ruleResult)
					ruleAsJson, err := MatchingRuleToJson(rule)
					assert.NotEmpty(t, ruleAsJson)
					assert.NoError(t, err)

					if tt.wantMatcherDefinitionType != "" {
						assert.Equal(t, tt.wantMatcherDefinitionType, ruleAsJson.Type)
					}
				}

				if tt.wantGeneratedValue != "" {
					generator := MatcherDefinitionGenerator(result)
					generated := GeneratorGenerateString(generator, "")
					assert.Equal(t, tt.wantGeneratedValue, generated)
				}
			})
		}
	})
}

func TestMatchingRuleFromJson(t *testing.T) {
	asJson := `{"match":"regex","regex":"[A-Za-z]"}`

	rule := MatchingRuleFromJson(asJson)

	res := MatchesStringValue(rule, "abc", "123", false)

	assert.Empty(t, res)
}
