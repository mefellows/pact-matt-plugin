package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/google/uuid"
	"github.com/mefellows/pact-matt-plugin/ffi"
	plugin "github.com/mefellows/pact-matt-plugin/io_pact_plugin"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type serverDetails struct {
	Port      int
	ServerKey string
}

// The shape of the JSON object given to the pact test
type configuration struct {
	Request  configurationRequest
	Response configurationResponse
}

type configurationRequest struct {
	Body string
}

type configurationResponse struct {
	Body string
}

func startPluginServer(details serverDetails) {
	log.Println("[INFO] server on port", details.Port)

	lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", details.Port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	fmt.Printf(`{"port": %d, "serverKey": "%s"}%s`, details.Port, details.ServerKey, "\n")

	var opts []grpc.ServerOption

	grpcServer := grpc.NewServer(opts...)
	plugin.RegisterPactPluginServer(grpcServer, newServer())
	grpcServer.Serve(lis)
}

func newServer() *mattPluginServer {
	s := &mattPluginServer{}
	return s
}

type mattPluginServer struct {
	plugin.UnimplementedPactPluginServer
}

// // Check that the plugin loaded OK. Returns the catalogue entries describing what the plugin provides
func (m *mattPluginServer) InitPlugin(ctx context.Context, req *plugin.InitPluginRequest) (*plugin.InitPluginResponse, error) {
	log.Println("[INFO] InitPlugin request:", req.Implementation, req.Version)

	return &plugin.InitPluginResponse{
		Catalogue: []*plugin.CatalogueEntry{
			{
				Key:  "matt",
				Type: plugin.CatalogueEntry_CONTENT_MATCHER,
				Values: map[string]string{
					"content-types": "text/matt;application/matt",
				},
			},
			{
				Key:  "matt",
				Type: plugin.CatalogueEntry_TRANSPORT,
			},
		},
	}, nil
}

// Use in the mock server
var expectedRequest, requestedResponse string

// Request to configure/setup the interaction for later verification. Data returned will be persisted in the pact file.
// Validate the request
// Setup the pact interaction (including parsing matching rules and setting up generators)
func (m *mattPluginServer) ConfigureInteraction(ctx context.Context, req *plugin.ConfigureInteractionRequest) (*plugin.ConfigureInteractionResponse, error) {
	log.Println("[INFO] ConfigureInteraction request:", req.ContentType, req.ContentsConfig)

	config, err := protoStructToConfigMap(req.ContentsConfig)

	log.Println("[INFO] ContentsConfig. Request:", config.Request.Body, "Response:", config.Response.Body, err)
	expectedRequest = config.Request.Body
	requestedResponse = config.Response.Body

	if err != nil {
		log.Println("[DEBUG] unmarshalling ContentsConfig from JSON:", err)
		return &plugin.ConfigureInteractionResponse{
			Error: err.Error(),
		}, nil
	}

	var interactions = make([]*plugin.InteractionResponse, 0)

	if config.Request.Body != "" {
		// Parse any expressions.
		// NOTE: this plugin only supports a basic string value, so it can also
		//       only support primitive values
		requestBodyValue, requestRules, requestGenerator, err := parseExpression(config.Request.Body)

		if err != nil {
			log.Println("[ERROR] unable to parse request expression:", err)
			return &plugin.ConfigureInteractionResponse{
				Error: err.Error(),
			}, nil
		}

		var generators map[string]*plugin.Generator

		if requestGenerator != nil {
			generators = map[string]*plugin.Generator{
				"$": generatorsToPluginGenerators(*requestGenerator),
			}
		}

		var matchingRules map[string]*plugin.MatchingRules

		if len(requestRules) > 0 {
			matchingRules = map[string]*plugin.MatchingRules{
				"$": {
					Rule: matchingRulesToPluginMatchingRules(requestRules),
				},
			}
		}

		interactions = append(interactions, &plugin.InteractionResponse{
			Contents: &plugin.Body{
				ContentType: "application/matt",
				Content:     wrapperspb.Bytes([]byte(generateMattMessage(requestBodyValue))),
			},
			PartName:   "request",
			Rules:      matchingRules,
			Generators: generators,
		})
	}

	if config.Response.Body != "" {

		responseBodyValue, responseRules, responseGenerator, err := parseExpression(config.Response.Body)
		if err != nil {
			log.Println("[ERROR] unable to parse response expression:", err)
			return &plugin.ConfigureInteractionResponse{
				Error: err.Error(),
			}, nil
		}

		var generators map[string]*plugin.Generator

		if responseGenerator != nil {
			generators = map[string]*plugin.Generator{
				"$": generatorsToPluginGenerators(*responseGenerator),
			}
		}

		var matchingRules map[string]*plugin.MatchingRules

		if len(responseRules) > 0 {
			matchingRules = map[string]*plugin.MatchingRules{
				"$": {
					Rule: matchingRulesToPluginMatchingRules(responseRules),
				},
			}
		}

		interactions = append(interactions, &plugin.InteractionResponse{
			Contents: &plugin.Body{
				ContentType: "application/matt",
				Content:     wrapperspb.Bytes([]byte(generateMattMessage(responseBodyValue))),
			},
			PartName:   "response",
			Rules:      matchingRules,
			Generators: generators,
		})
	}

	return &plugin.ConfigureInteractionResponse{
		Interaction: interactions,
	}, nil
}

// Store mismatches for re-use in GetMockServerResults
// TODO: this doesn't work - comparecontetns isn't colled for
var mismatches = make(map[string]*plugin.ContentMismatches)

// Request to perform a comparison of some contents (matching request)
// This is not used for plugins that also provide a transport,
// so the matching functions should be separated into a shared function
func (m *mattPluginServer) CompareContents(ctx context.Context, req *plugin.CompareContentsRequest) (*plugin.CompareContentsResponse, error) {
	log.Println("[INFO] CompareContents request:", req)

	actual := parseMattMessage(string(req.Actual.Content.Value))
	expected := parseMattMessage(string(req.Expected.Content.Value))

	// 1. Extract the actual and expected values (bytes)
	// 2. Do something protocol specific, to read in the data structure of both sides
	// 3. Compare actual vs expected
	//    returse the actual data structure, and for each attribute, apply matching rule (test the matching rule)

	// {
	// 	foo: {               -> was there a matching rule at path `$.foo`, and then does value for path matching
	// 		bar: [{
	// 			baz: 1,
	// 			foo: "string",
	// 			...
	// 		}]
	// 	}
	// }

	// // JSON Path expressions
	// // $.foo.bar[*].baz,

	mismatch := applyMatchingRules("$", expected, actual, req.Rules)

	// TODO: extract matching rules!
	// TODO: can we do a "matching_rule_from_json" ffi method?

	if mismatch != nil {
		log.Println("[INFO] found:", mismatch)

		mismatches = map[string]*plugin.ContentMismatches{
			// "foo.bar.baz...." // hierarchical
			// "column:1" // tabular
			"$": {
				Mismatches: []*plugin.ContentMismatch{
					{
						Expected: wrapperspb.Bytes([]byte(expected)),
						Actual:   wrapperspb.Bytes([]byte(actual)),
						Mismatch: mismatch.Error(),
						Path:     "$",
					},
				},
			},
		}

		return &plugin.CompareContentsResponse{
			Results: mismatches,
		}, nil
	}

	return &plugin.CompareContentsResponse{}, nil

}

// Request to generate the content using any defined generators
// If there are no generators, this should just return back the given data
func (m *mattPluginServer) GenerateContent(ctx context.Context, req *plugin.GenerateContentRequest) (*plugin.GenerateContentResponse, error) {
	log.Println("[INFO] GenerateContent request:", req.Contents, req.Generators, req.PluginConfiguration)

	var config configuration
	err := json.Unmarshal(req.Contents.Content.Value, &config)

	if err != nil {
		log.Println("[INFO] :", err)
	}

	return &plugin.GenerateContentResponse{
		Contents: &plugin.Body{
			ContentType: "application/matt",
			Content:     wrapperspb.Bytes([]byte(generateMattMessage(config.Response.Body))),
		},
	}, nil

}

// Updated catalogue. This will be sent when the core catalogue has been updated (probably by a plugin loading).
func (m *mattPluginServer) UpdateCatalogue(ctx context.Context, cat *plugin.Catalogue) (*emptypb.Empty, error) {
	log.Println("[INFO] UpdateCatalogue request:", cat.Catalogue)

	return &emptypb.Empty{}, nil
}

// Start a mock server
func (m *mattPluginServer) StartMockServer(ctx context.Context, req *plugin.StartMockServerRequest) (*plugin.StartMockServerResponse, error) {
	log.Println("[INFO] StartMockServer request:", req)
	var err error
	port := int(req.Port)

	id := uuid.NewString()
	if port == 0 {
		port, err = GetFreePort()
		if err != nil {
			log.Println("[INFO] unable to find a free port:", err)
			return &plugin.StartMockServerResponse{
				Response: &plugin.StartMockServerResponse_Error{
					Error: err.Error(),
				},
			}, err
		}
	}

	go startTCPServer(id, port, expectedRequest, requestedResponse, mismatches)

	return &plugin.StartMockServerResponse{
		Response: &plugin.StartMockServerResponse_Details{
			Details: &plugin.MockServerDetails{
				Key:     id,
				Port:    uint32(port),
				Address: fmt.Sprintf("tcp://%s:%d", req.HostInterface, port),
			},
		},
	}, nil

	// TODO: parse the interactions and then store for future responses
}

// Shutdown a running mock server
func (m *mattPluginServer) ShutdownMockServer(ctx context.Context, req *plugin.ShutdownMockServerRequest) (*plugin.ShutdownMockServerResponse, error) {
	log.Println("[INFO] ShutdownMockServer request:", req)

	err := stopTCPServer(req.ServerKey)
	if err != nil {
		return &plugin.ShutdownMockServerResponse{ // duplicate / same info to GetMockServerResults
			Ok: false,
			Results: []*plugin.MockServerResult{
				{
					Error: err.Error(),
				},
			},
		}, nil
	}

	return &plugin.ShutdownMockServerResponse{ // duplicate / same info to GetMockServerResults
		Ok:      true,
		Results: []*plugin.MockServerResult{},
	}, nil

}

// Get the matching results from a running mock server
func (m *mattPluginServer) GetMockServerResults(ctx context.Context, req *plugin.MockServerRequest) (*plugin.MockServerResults, error) {
	log.Println("[INFO] GetMockServerResults request:", req)

	// TODO: error if server not called, or mismatches found
	// ComtpareContents won't get called if there is a mock server. in protobufs,

	// The mock server is responsible for comparing its contents
	// In the case of a plugin that implements both content + Protocols, you would likely share the mismatch function
	// or persist the mismatches (as is the case here)
	if len(mismatches) > 0 {
		results := make([]*plugin.MockServerResult, 0)

		for path, mismatch := range mismatches {
			results = append(results, &plugin.MockServerResult{
				Path:       path,
				Mismatches: mismatch.Mismatches,
			})
		}

		return &plugin.MockServerResults{
			Results: results,
		}, nil
	}

	return &plugin.MockServerResults{}, nil
}

var requestMessage = ""
var responseMessage = ""

// Prepare an interaction for verification. This should return any data required to construct any request
// so that it can be amended before the verification is run
// Example: authentication headers
// If no modification is necessary, this should simply send the unmodified request back to the framework
func (m *mattPluginServer) PrepareInteractionForVerification(ctx context.Context, req *plugin.VerificationPreparationRequest) (*plugin.VerificationPreparationResponse, error) {
	// 2022/10/27 23:06:42 Received PrepareInteractionForVerification request: pact:"{\"consumer\":{\"name\":\"matttcpconsumer\"},\"interactions\":[{\"description\":\"Matt message\",\"key\":\"f27f2917655cb542\",\"pending\":false,\"request\":{\"contents\":{\"content\":\"MATThellotcpMATT\",\"contentType\":\"application/matt\",\"contentTypeHint\":\"DEFAULT\",\"encoded\":false}},\"response\":[{\"contents\":{\"content\":\"MATTtcpworldMATT\",\"contentType\":\"application/matt\",\"contentTypeHint\":\"DEFAULT\",\"encoded\":false}}],\"transport\":\"matt\",\"type\":\"Synchronous/Messages\"}],\"metadata\":{\"pactRust\":{\"ffi\":\"0.3.13\",\"mockserver\":\"0.9.4\",\"models\":\"0.4.5\"},\"pactSpecification\":{\"version\":\"4.0\"},\"plugins\":[{\"configuration\":{},\"name\":\"matt\",\"version\":\"0.0.1\"}]},\"provider\":{\"name\":\"matttcpprovider\"}}" interactionKey:"f27f2917655cb542" config:{fields:{key:"host" value:{string_value:"localhost"}} fields:{key:"port" value:{number_value:8444}}}
	log.Println("[INFO] PrepareInteractionForVerification request:", req)

	requestMessage, responseMessage = extractRequestAndResponseMessages(req.Pact, req.InteractionKey)

	log.Println("[DEBUG] request body:", requestMessage)
	log.Println("[DEBUG] response body:", responseMessage)

	return &plugin.VerificationPreparationResponse{
		Response: &plugin.VerificationPreparationResponse_InteractionData{
			InteractionData: &plugin.InteractionData{
				Body: &plugin.Body{
					ContentType: "application/matt",
					Content:     wrapperspb.Bytes([]byte(generateMattMessage(requestMessage))), // <- TODO: this needs to come from the pact struct
				},
			},
		},
	}, nil

}

// Execute the verification for the interaction.
func (m *mattPluginServer) VerifyInteraction(ctx context.Context, req *plugin.VerifyInteractionRequest) (*plugin.VerifyInteractionResponse, error) {
	log.Println("[INFO] received VerifyInteraction request:", req)

	// Issue the call to the provider
	host := req.Config.AsMap()["host"].(string)
	port := req.Config.AsMap()["port"].(float64)

	log.Println("[INFO] calling TCP service at host", host, "and port", port)
	actual, err := callMattServiceTCP(host, int(port), requestMessage)
	log.Println("[INFO] actual:", actual, "wanted:", responseMessage, "err:", err)

	// Report on the results
	if actual != responseMessage {
		return &plugin.VerifyInteractionResponse{
			Response: &plugin.VerifyInteractionResponse_Result{
				Result: &plugin.VerificationResult{
					Success: false,
					Output:  []string{""},
					Mismatches: []*plugin.VerificationResultItem{
						{
							Result: &plugin.VerificationResultItem_Mismatch{
								Mismatch: &plugin.ContentMismatch{
									Expected: wrapperspb.Bytes([]byte(responseMessage)),
									Actual:   wrapperspb.Bytes([]byte(actual)),
									Path:     "$",
									Mismatch: fmt.Sprintf("Expected '%s' but got '%s'", responseMessage, actual),
								},
							},
						},
					},
				},
			},
		}, nil
	}

	return &plugin.VerifyInteractionResponse{
		Response: &plugin.VerifyInteractionResponse_Result{
			Result: &plugin.VerificationResult{
				Success: true,
			},
		},
	}, nil

}

func protoStructToConfigMap(s *structpb.Struct) (configuration, error) {
	var config configuration
	bytes, err := s.MarshalJSON()

	if err != nil {
		log.Println("[ERROR] error marshalling ContentsConfig to JSON:", err)
		return config, nil
	}

	err = json.Unmarshal(bytes, &config)

	if err != nil {
		log.Println("[ERROR] error unmarshalling ContentsConfig from JSON:", err)
		return config, nil
	}

	return config, nil
}

// GetFreePort Gets an available port by asking the kernal for a random port
// ready and available for use.
func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	defer l.Close()
	return port, nil
}

// Accepts a Pact JSON string and interactionKey, and extracts the relevant messages
func extractRequestAndResponseMessages(pact string, interactionKey string) (request string, response string) {
	var p pactv4
	err := json.Unmarshal([]byte(pact), &p)
	if err != nil {
		log.Println("[ERROR] unable to extract payload for verification:", err)
	}

	// Find the current interaction in the Pact
	for _, inter := range p.Interactions {
		log.Println("[DEBUG] looking for interaction by key", interactionKey)
		log.Println(inter)

		switch i := inter.(type) {
		case *httpInteraction:
			log.Println("[DEBUG] keys", i.interaction.Key, interactionKey)
			if i.Key == interactionKey {
				log.Println("[DEBUG] HTTP interaction")
				return parseMattMessage(i.Request.Body.Content), parseMattMessage(i.Response.Body.Content)
			}
		case *asyncMessageInteraction:
			log.Println("[DEBUG] keys", i.interaction.Key, interactionKey)
			if i.Key == interactionKey {
				log.Println("[DEBUG] async interaction")
				return parseMattMessage(i.Contents.Content), ""
			}
		case *syncMessageInteraction:
			log.Println("[DEBUG] keys", i.interaction.Key, interactionKey)
			if i.Key == interactionKey {
				log.Println("[DEBUG] sync interaction")
				return parseMattMessage(i.Request.Contents.Content), parseMattMessage(i.Response[0].Contents.Content)
			}
		default:
			log.Printf("unknown interaction type: '%+v'", i)

			return "", ""
		}
	}

	return "", ""
}

func parseExpression(expression string) (value string, rules []ffi.MatchingRule, generator *ffi.Generator, err error) {
	log.Println("parseExpression:", expression)
	result := ffi.ParseMatcherDefinition(expression)
	rules = make([]ffi.MatchingRule, 0)

	if result == nil {
		log.Println("[INFO] no expression detected")
		return value, rules, generator, err
	}

	log.Printf("[DEBUG] check expression parsing error")
	err = ffi.MatcherDefinitionError(result)
	if err != nil {
		log.Println("err", err)
		return value, rules, generator, err
	}
	log.Printf("no error, getting value")

	value = ffi.MatcherDefinitionValue(result)
	log.Println("value", value)

	iter := ffi.MatcherDefinitionIter(result)
	log.Println("iter", iter)
	ruleResult := ffi.MatchingRuleIterNext(iter)
	log.Println("ruleResult", ruleResult)

	if ruleResult != nil {
		log.Println("ruleResult not nil")
		rule := ffi.MatchingRulePtr(ruleResult)
		log.Println("rule", rule)
		ruleAsJson, err := ffi.MatchingRuleToJson(rule)
		log.Println("ruleAsJson", ruleAsJson, "err", err)
		log.Println("ruleAsJson", ruleAsJson, "err", err)
		if err != nil {
			return value, rules, generator, err
		}

		rules = append(rules, ruleAsJson)
	}

	generatorPtr := ffi.MatcherDefinitionGenerator(result)
	log.Println("generatorPtr", generatorPtr)

	if generatorPtr != nil {
		log.Println("generatorPtr not nil")
		g, err := ffi.GeneratorToJSON(generatorPtr)
		log.Println("generator", generator, "err", err)
		generator = &g

		if err != nil {
			return value, rules, generator, err
		}
	}

	return value, rules, generator, err
}

func matchingRulesToPluginMatchingRules(rules []ffi.MatchingRule) []*plugin.MatchingRule {
	matchingRules := make([]*plugin.MatchingRule, 0)

	for _, r := range rules {
		values, err := structpb.NewStruct(r.Values)

		if err != nil {
			log.Println("[ERROR] unable to serialise matching rule into a protobof struct", err)
			return nil
		}

		matchingRules = append(matchingRules, &plugin.MatchingRule{
			Type:   r.Type,
			Values: values,
		})
	}

	return matchingRules
}

func generatorsToPluginGenerators(g ffi.Generator) *plugin.Generator {
	values, err := structpb.NewStruct(g.Values)

	if err != nil {
		log.Println("[ERROR] unable to serialise generator into a protobof struct", err)
		return nil
	}

	return &plugin.Generator{
		Type:   g.Type,
		Values: values,
	}
}

// Rules will be keyed by the path
func rulesFromProtobufMatchingRules(rules map[string]*plugin.MatchingRules) map[string][]ffi.MatchingRule {
	log.Println("[DEBUG] rulesFromProtobufMatchingRules")
	result := make(map[string][]ffi.MatchingRule, len(rules))

	for k, v := range rules {
		log.Println("[DEBUG] transforming a rule")
		transformed := make([]ffi.MatchingRule, 0)

		for _, r := range v.Rule {
			transformed = append(transformed, ffi.MatchingRule{
				Type:   r.Type,
				Values: r.Values.AsMap(),
			})
		}

		result[k] = transformed
		log.Println("[DEBUG] transformed", len(result[k]), "rules")
	}

	return result
}

// TODO: should this be an array of errors?
func applyMatchingRules(path string, expected string, actual string, rawRules map[string]*plugin.MatchingRules) error {
	log.Println("[DEBUG] applyMatchingRules")
	rules := rulesFromProtobufMatchingRules(rawRules)

	// No matchers? Perform a straight diff
	if len(rawRules) == 0 {
		log.Println("[DEBUG] no rules, direct match")
		if actual != expected {
			return fmt.Errorf("expected body '%s' is not equal to actual body '%s'", expected, actual)
		}
	}
	log.Println("[DEBUG] found rules, applying them")

	// Apply matchers. Probably, this should return multiple errors
	pathRules, ok := rules[path]
	if !ok {
		return nil
	}

	for _, r := range pathRules {
		log.Println("[DEBUG] converting rule to JSON", r)
		bytes, err := json.Marshal(r)
		if err != nil {
			return err
		}
		log.Println("[DEBUG] have rule as JSON", string(bytes))

		matchingRule := ffi.MatchingRuleFromJson(string(bytes))
		if matchingRule == nil {
			return fmt.Errorf("unable to parse matching rule JSON, context: '%s'", string(bytes))
		}
		log.Println("[DEBUG] have matching rule", matchingRule)

		if matchingRule == nil {
			return fmt.Errorf("unable to parse matching rule, nil pointer received from 'MatchingRuleFromJson'")
		}

		mismatch := ffi.MatchesStringValue(matchingRule, expected, actual, false)

		if mismatch != "" {
			return errors.New(mismatch)
		}
	}

	return nil
}
