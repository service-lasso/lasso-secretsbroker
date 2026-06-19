package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

const mcpProtocolVersion = "2025-11-25"

type mcpToolDefinition struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitempty"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

type mcpToolsResponse struct {
	ServiceID       string              `json:"serviceId"`
	APIVersion      string              `json:"apiVersion"`
	ProtocolVersion string              `json:"protocolVersion"`
	Outcome         string              `json:"outcome"`
	Tools           []mcpToolDefinition `json:"tools"`
	Safety          mcpSafety           `json:"safety"`
}

type mcpToolCallResponse struct {
	Content           []mcpTextContent `json:"content"`
	StructuredContent any              `json:"structuredContent,omitempty"`
	IsError           bool             `json:"isError"`
	Safety            mcpSafety        `json:"safety"`
}

type mcpTextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpSafety struct {
	MetadataOnly          bool `json:"metadataOnly"`
	ValueMaterialIncluded bool `json:"valueMaterialIncluded"`
	MutatingToolsEnabled  bool `json:"mutatingToolsEnabled"`
}

type mcpUnsupportedResponse struct {
	ServiceID  string `json:"serviceId"`
	APIVersion string `json:"apiVersion"`
	Tool       string `json:"tool"`
	Outcome    string `json:"outcome"`
	Reason     string `json:"reason"`
	NextAction string `json:"nextAction"`
}

func runAdminMCP(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("unknown admin mcp command %q", "")
	}
	switch args[0] {
	case "tools":
		fs := flag.NewFlagSet("admin mcp tools", flag.ContinueOnError)
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		return encodeAdminJSON(out, mcpToolsResponse{
			ServiceID:       serviceID,
			APIVersion:      apiVersion,
			ProtocolVersion: mcpProtocolVersion,
			Outcome:         "ready",
			Tools:           mcpToolDefinitions(),
			Safety:          defaultMCPSafety(),
		})
	case "call":
		return runAdminMCPCall(args[1:], out)
	default:
		return fmt.Errorf("unknown admin mcp command %q", args[0])
	}
}

func runAdminMCPCall(args []string, out io.Writer) error {
	fs, opts := newAdminFlagSet("admin mcp call")
	tool := fs.String("tool", "", "MCP tool name")
	query := fs.String("query", "", "metadata search query for tools that support it")
	since := fs.String("since", "", "RFC3339 lower event time bound")
	until := fs.String("until", "", "RFC3339 upper event time bound")
	serviceIDFilter := fs.String("service-id", "", "event service id filter")
	providerID := fs.String("provider-id", "", "event provider id filter")
	operation := fs.String("operation", "", "event operation filter")
	outcome := fs.String("outcome", "", "event outcome filter")
	severity := fs.String("severity", "", "event severity filter")
	family := fs.String("family", "", "event family filter")
	refPrefix := fs.String("ref-prefix", "", "safe event ref prefix filter")
	refHash := fs.String("ref-hash", "", "event ref hash filter")
	limit := fs.Int("limit", defaultOperationalEventLimit, "event page size")
	cursor := fs.Int("cursor", 0, "event page cursor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	backend, material, err := backendFromAdminOptions(opts)
	if err != nil && !errors.Is(err, errLocked) {
		return err
	}

	var result mcpToolCallResponse
	switch strings.TrimSpace(*tool) {
	case "secretsbroker.status":
		statusState := normalizeAdminState("", backend, material)
		recovery, recoveryErr := backend.recoveryPolicyStatus()
		if recoveryErr != nil && statusState == "ready" {
			statusState = "degraded"
		}
		value := adminStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Outcome: statusState, Health: defaultHealth(statusState), Status: defaultStatus(statusState), State: defaultState(statusState), Key: keyStatus(material), Providers: backend.providerConfigStatusResponse(), Recovery: recovery}
		result, err = mcpToolResult(value, false)
	case "secretsbroker.sources.status":
		result, err = mcpToolResult(sourceStatusResponse{ServiceID: serviceID, APIVersion: apiVersion, Sources: defaultSourceRegistry(backend).Sources}, false)
	case "secretsbroker.providers.status":
		result, err = mcpToolResult(backend.providerConfigStatusResponse(), false)
	case "secretsbroker.telemetry.summary":
		value, callErr := buildTelemetryResponse(backend)
		result, err = mcpToolResult(value, callErr != nil)
	case "secretsbroker.events.list":
		values := url.Values{}
		values.Set("limit", strconv.Itoa(*limit))
		values.Set("cursor", strconv.Itoa(*cursor))
		for key, value := range map[string]string{
			"since":      *since,
			"until":      *until,
			"serviceId":  *serviceIDFilter,
			"providerId": *providerID,
			"operation":  *operation,
			"outcome":    *outcome,
			"severity":   *severity,
			"family":     *family,
			"refPrefix":  *refPrefix,
			"refHash":    *refHash,
		} {
			if strings.TrimSpace(value) != "" {
				values.Set(key, value)
			}
		}
		filters, filterErr := parseEventFilters(values)
		if filterErr != nil {
			return filterErr
		}
		value, callErr := buildEventsResponse(opts.EventsPath, filters)
		result, err = mcpToolResult(value, callErr != nil)
	case "secretsbroker.secrets.metadata.list":
		value, callErr := backend.listManagedSecrets(*query, false)
		result, err = mcpToolResult(value, callErr != nil)
	case "secretsbroker.secrets.reveal", "secretsbroker.secrets.write", "secretsbroker.secrets.rotate":
		result, err = mcpToolResult(mcpUnsupportedResponse{
			ServiceID:  serviceID,
			APIVersion: apiVersion,
			Tool:       strings.TrimSpace(*tool),
			Outcome:    "unsupported",
			Reason:     "Secret-bearing and mutating MCP tools are disabled in the first adapter slice.",
			NextAction: "use existing authenticated admin/API workflows or implement a separately approved MCP guarded flow",
		}, true)
	case "":
		return fmt.Errorf("missing --tool")
	default:
		return fmt.Errorf("unknown MCP tool %q", *tool)
	}
	if err != nil {
		return err
	}
	return encodeAdminJSON(out, result)
}

func mcpToolDefinitions() []mcpToolDefinition {
	readOnly := map[string]any{"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true}
	disabled := map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false}
	return []mcpToolDefinition{
		{Name: "secretsbroker.status", Title: "Secrets Broker Status", Description: "Return broker lifecycle, key, provider, and recovery metadata without secret values.", InputSchema: emptyMCPSchema(), Annotations: readOnly},
		{Name: "secretsbroker.sources.status", Title: "Secrets Broker Source Status", Description: "Return source capability and lifecycle metadata.", InputSchema: emptyMCPSchema(), Annotations: readOnly},
		{Name: "secretsbroker.providers.status", Title: "Secrets Broker Provider Status", Description: "Return provider configuration status with credential handles only.", InputSchema: emptyMCPSchema(), Annotations: readOnly},
		{Name: "secretsbroker.telemetry.summary", Title: "Secrets Broker Telemetry Summary", Description: "Return low-cardinality operational counters and safety flags.", InputSchema: emptyMCPSchema(), Annotations: readOnly},
		{Name: "secretsbroker.events.list", Title: "Secrets Broker Events", Description: "List bounded metadata-only operational events with safe filters.", InputSchema: eventMCPSchema(), Annotations: readOnly},
		{Name: "secretsbroker.secrets.metadata.list", Title: "Secrets Broker Secret Metadata", Description: "List/search managed secret metadata without reveal values.", InputSchema: queryMCPSchema(), Annotations: readOnly},
		{Name: "secretsbroker.secrets.reveal", Title: "Secrets Broker Secret Reveal Disabled", Description: "Disabled boundary marker for secret reveal requests; returns unsupported.", InputSchema: emptyMCPSchema(), Annotations: disabled},
		{Name: "secretsbroker.secrets.write", Title: "Secrets Broker Secret Write Disabled", Description: "Disabled boundary marker for write requests; returns unsupported.", InputSchema: emptyMCPSchema(), Annotations: disabled},
		{Name: "secretsbroker.secrets.rotate", Title: "Secrets Broker Secret Rotate Disabled", Description: "Disabled boundary marker for rotate requests; returns unsupported.", InputSchema: emptyMCPSchema(), Annotations: disabled},
	}
}

func emptyMCPSchema() map[string]any {
	return map[string]any{"type": "object", "additionalProperties": false}
}

func queryMCPSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"query": map[string]any{"type": "string", "description": "Metadata search query."},
		},
	}
}

func eventMCPSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"properties": map[string]any{
			"since":      map[string]any{"type": "string", "description": "RFC3339 lower time bound."},
			"until":      map[string]any{"type": "string", "description": "RFC3339 upper time bound."},
			"serviceId":  map[string]any{"type": "string"},
			"providerId": map[string]any{"type": "string"},
			"operation":  map[string]any{"type": "string"},
			"outcome":    map[string]any{"type": "string"},
			"severity":   map[string]any{"type": "string"},
			"family":     map[string]any{"type": "string"},
			"refPrefix":  map[string]any{"type": "string"},
			"refHash":    map[string]any{"type": "string"},
			"limit":      map[string]any{"type": "integer", "minimum": 1, "maximum": maxOperationalEventLimit},
			"cursor":     map[string]any{"type": "integer", "minimum": 0},
		},
	}
}

func mcpToolResult(value any, isError bool) (mcpToolCallResponse, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return mcpToolCallResponse{}, err
	}
	return mcpToolCallResponse{
		Content:           []mcpTextContent{{Type: "text", Text: string(encoded)}},
		StructuredContent: value,
		IsError:           isError,
		Safety:            defaultMCPSafety(),
	}, nil
}

func defaultMCPSafety() mcpSafety {
	return mcpSafety{MetadataOnly: true, ValueMaterialIncluded: false, MutatingToolsEnabled: false}
}
