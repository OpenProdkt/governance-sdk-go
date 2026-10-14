package governance

import (
	"fmt"
	"strings"
)

type AssetIdentity struct {
	Application string
	Service     string
	Environment string
}

func GenerateAssetKey(identity AssetIdentity) (string, error) {
	components := []struct {
		name  string
		value string
	}{
		{name: "application", value: identity.Application},
		{name: "service", value: identity.Service},
		{name: "environment", value: identity.Environment},
	}
	for _, component := range components {
		if !isCanonicalAssetKeyComponent(component.value) {
			return "", fmt.Errorf("%s must be a lowercase ASCII DNS label (1-63 characters)", component.name)
		}
	}
	return strings.Join([]string{identity.Application, identity.Service, identity.Environment}, "."), nil
}

func isCanonicalAssetKeyComponent(component string) bool {
	if len(component) == 0 || len(component) > 63 {
		return false
	}
	for index, character := range []byte(component) {
		isLowercaseLetter := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		if !isLowercaseLetter && !isDigit && character != '-' {
			return false
		}
		if character == '-' && (index == 0 || index == len(component)-1) {
			return false
		}
	}
	return true
}
