package main

import (
	"errors"
	"regexp"
	"strings"
)

var ramSecretSelector = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$`)
var ramTemplateSelector = regexp.MustCompile(`\$\{([^{}]+)\}`)

func ramBindingRefs(bindings []ramSecretBinding) ([]string, error) {
	if len(bindings) > 128 {
		return nil, errors.New("too many bindings")
	}
	refs := []string{}
	selectors := map[string]bool{}
	seen := map[string]bool{}
	for _, binding := range bindings {
		if len(binding.Selector) > 256 || !ramSecretSelector.MatchString(binding.Selector) || !validSecretRef(binding.Ref) || selectors[binding.Selector] {
			return nil, errors.New("invalid binding")
		}
		selectors[binding.Selector] = true
		if !seen[binding.Ref] {
			refs = append(refs, binding.Ref)
			seen[binding.Ref] = true
		}
	}
	return refs, nil
}

// Resolve inside Broker; neither values nor rendered bytes go back to Core.
func (b *localBackend) renderRAMSecretFiles(files []ramFileInput, bindings []ramSecretBinding, identity resolveRequest) ([]ramFileInput, error) {
	if len(files) == 0 || len(files) > 128 {
		return nil, errors.New("invalid file count")
	}
	// Bound secret-free templates before executing any source adapter.
	total := 0
	for _, file := range files {
		if !validRAMFilePath(file.Path) || len(file.Content) > maxRAMFileBytes {
			return nil, errors.New("invalid template")
		}
		total += len(file.Content)
		if total > maxRAMGrantBytes {
			return nil, errors.New("templates too large")
		}
	}
	// The original grant API accepted already-rendered bytes. An omitted binding
	// list preserves those bytes literally, including dollar-brace text in a
	// credential. New Core sends an explicit list and requests Broker rendering.
	if bindings == nil {
		return files, nil
	}
	byRef := map[string]resolveResult{}
	if len(bindings) > 0 {
		for _, result := range b.resolve(identity).Results {
			byRef[result.Ref] = result
		}
	}
	values := map[string]string{}
	for _, binding := range bindings {
		result, found := byRef[binding.Ref]
		if found && result.Outcome == "ready" {
			values[binding.Selector] = result.Value
		} else if binding.Required {
			return nil, errors.New("required secret unavailable")
		}
	}
	outputs := make([]ramFileInput, 0, len(files))
	total = 0
	for _, file := range files {
		content, err := renderRAMTemplate(file.Content, values)
		if err != nil {
			return nil, err
		}
		total += len(content)
		if total > maxRAMGrantBytes {
			return nil, errors.New("rendered grant too large")
		}
		outputs = append(outputs, ramFileInput{Path: file.Path, Content: content})
	}
	return outputs, nil
}

func renderRAMTemplate(template string, values map[string]string) (string, error) {
	var output strings.Builder
	end := 0
	for _, match := range ramTemplateSelector.FindAllStringSubmatchIndex(template, -1) {
		literal := template[end:match[0]]
		value, ok := values[template[match[2]:match[3]]]
		if !ok || strings.Contains(literal, "${") || len(literal)+len(value) > maxRAMFileBytes-output.Len() {
			return "", errors.New("unresolved or excessive content")
		}
		output.WriteString(literal)
		output.WriteString(value)
		end = match[1]
	}
	literal := template[end:]
	if strings.Contains(literal, "${") || len(literal) > maxRAMFileBytes-output.Len() {
		return "", errors.New("unresolved or excessive content")
	}
	output.WriteString(literal)
	return output.String(), nil
}
