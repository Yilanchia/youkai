package web

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"youkai/internal/discipline"
	"youkai/internal/ledger"
)

// GraphQL introspection: read the schema, touch nothing else.
//
// One request, one query. The introspection query is a constant in this file; the
// capability never runs a query or a mutation, never pages through data, and never
// builds a query from target-controlled text. What it returns is a schema map, and
// mutations are labelled as writes so the autonomous loop will not go near them.

// introspectionQuery is the standard schema query. Kept compact: we need names and
// kinds, not descriptions or deprecation metadata.
const introspectionQuery = `query YoukaiIntrospect {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields {
        name
        args { name }
        type { kind name ofType { kind name } }
      }
    }
  }
}`

func runGraphQLIntrospect(ctx context.Context, env *Env, args map[string]any) (ledger.Observation, error) {
	rawURL, err := requiredString(args, "url")
	if err != nil {
		return ledger.Observation{}, err
	}
	body, _ := json.Marshal(map[string]any{"query": introspectionQuery})

	res, err := do(ctx, env, discipline.Request{
		Method: "POST", URL: rawURL, Purpose: "graphql_introspect",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    body, FollowRedirects: true,
	})
	if err != nil {
		return ledger.Observation{}, fmt.Errorf("web: graphql_introspect: %w", err)
	}

	b := newObs()
	b.requestID(res.RequestID)
	ev := map[string]any{"request_id": res.RequestID, "url": rawURL, "source": "graphql"}

	var payload struct {
		Data struct {
			Schema struct {
				QueryType    *struct{ Name string } `json:"queryType"`
				MutationType *struct{ Name string } `json:"mutationType"`
				Types        []struct {
					Kind   string `json:"kind"`
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string `json:"name"`
						} `json:"args"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	parseErr := json.Unmarshal(res.Body, &payload)
	schema := payload.Data.Schema
	if parseErr != nil || (schema.QueryType == nil && schema.MutationType == nil && len(schema.Types) == 0) {
		// Introspection disabled or answered with an error: say so, do not guess.
		reason := "introspection 不可用"
		if len(payload.Errors) > 0 {
			reason += ":" + payload.Errors[0].Message
		} else if parseErr != nil {
			reason += ":响应不是可解析的 introspection JSON"
		} else if res.Status >= 400 {
			reason += fmt.Sprintf(":HTTP %d", res.Status)
		}
		b.fact("GraphQL "+reason+"(不推断 schema)", ev, "graphql", "introspection-disabled")
		b.setSummary("graphql_introspect: introspection 不可用")
		return b.obs, nil
	}

	queries, mutations := 0, 0
	for _, t := range schema.Types {
		if strings.HasPrefix(t.Name, "__") {
			continue
		}
		rootQuery := schema.QueryType != nil && t.Name == schema.QueryType.Name
		rootMutation := schema.MutationType != nil && t.Name == schema.MutationType.Name
		if !rootQuery && !rootMutation {
			continue
		}
		for _, f := range t.Fields {
			fieldURL := "graphql:" + rawURL + "#" + t.Name + "." + f.Name
			argNames := make([]string, 0, len(f.Args))
			for _, a := range f.Args {
				argNames = append(argNames, a.Name)
			}
			if rootMutation {
				mutations++
				b.asset("endpoint", fieldURL)
				b.fact(fmt.Sprintf("GraphQL mutation:%s.%s(args=%s)", t.Name, f.Name, strings.Join(argNames, ",")),
					ev, "graphql", "mutation", "write", "tier-hint=proof")
				continue
			}
			queries++
			b.asset("endpoint", fieldURL)
			b.fact(fmt.Sprintf("GraphQL query:%s.%s(args=%s)", t.Name, f.Name, strings.Join(argNames, ",")),
				ev, "graphql", "query", "source=graphql")
		}
	}

	b.finding(ledger.FindingSeed{
		Title:    "GraphQL introspection 开放",
		Severity: "info",
		Kind:     "exposure",
		Where:    rawURL,
		Detail: fmt.Sprintf("introspection 可直接读取:暴露 %d 个 query、%d 个 mutation。"+
			"生产端点通常应关闭它;mutation 属写操作,youkai 不会自动执行。", queries, mutations),
		Evidence: ev,
		Tags:     []string{"graphql", "introspection", "exposure"},
		Anchors:  []string{"surface:" + rawURL},
	})
	b.setSummary(fmt.Sprintf("graphql_introspect: %d query / %d mutation", queries, mutations))
	return b.obs, nil
}
