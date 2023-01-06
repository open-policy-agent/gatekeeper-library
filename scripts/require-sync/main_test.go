package main

import (
	"strings"
	"testing"
)

func TestValidateRequiresSyncDataContent(t *testing.T) {
	testCases := []struct {
		name          string
		template      string
		expectedBool  bool
		expectedError bool
		}{
			{
				name: "valid",
				template: "\"[[ {\"groups\":[\"\"], \"versions\": [\"v1\"], \"kinds\": [\"Service\"] }]]\"",
				expectedBool: true,
				expectedError: false,
			},
			{
				name: "invalid",
				template: "\"[[ {\"group\":[\"\"], \"version\": [\"v1\"], \"kind\": [\"Service\"] }]]\"",
				expectedBool: false,
				expectedError: true,
			},
		}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bool, _ := validateRequiresSyncDataContent(strings.TrimSpace(tc.template))
			if bool != tc.expectedBool && !tc.expectedError {
				t.Errorf("expected bool to be %t, got %t", tc.expectedBool, bool)
			}
		})
	}

}
