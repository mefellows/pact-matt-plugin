package ffi

import (
	"encoding/json"
	"fmt"
)

type MatchingRule struct {
	Values map[string]interface{} `json:"values"`
	Type   string                 `json:"match"`
}

func (m *MatchingRule) UnmarshalJSON(b []byte) error {
	var rule map[string]interface{}

	err := json.Unmarshal(b, &rule)
	if err != nil {
		return err
	}

	match, ok := rule["match"]
	if !ok {
		return fmt.Errorf("missing mandatory field 'match'")
	} else {
		m.Type = match.(string)
		delete(rule, "match")
	}
	m.Values = rule

	return nil
}

func (m MatchingRule) MarshalJSON() ([]byte, error) {
	mappedOutput := make(map[string]interface{}, 0)

	mappedOutput["match"] = m.Type
	for k, v := range m.Values {
		mappedOutput[k] = v
	}

	return json.Marshal(mappedOutput)
}

type Generator MatchingRule

func GetRulesFromExpression(expression string) ([]MatchingRule, []Generator, error) {
	result := ParseMatcherDefinition(expression)
	rules := make([]MatchingRule, 0)
	generators := make([]Generator, 0)

	err := MatcherDefinitionError(result)
	if err != nil {
		return nil, nil, err
	}

	iter := MatcherDefinitionIter(result)
	ruleResult := MatchingRuleIterNext(iter)

	for ruleResult != nil {
		rule := MatchingRulePtr(ruleResult)
		ruleAsJson, err := MatchingRuleToJson(rule)

		if err != nil {
			return nil, nil, err
		}

		rules = append(rules, ruleAsJson)

		generator := MatcherDefinitionGenerator(result)
		generatorAsJSON, err := GeneratorToJSON(generator)
		if err != nil {
			return nil, nil, err
		}
		generators = append(generators, generatorAsJSON)

	}

	return rules, generators, nil
}
