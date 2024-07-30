/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package model

import (
	"fmt"
	"strings"

	"github.com/eclipse-symphony/symphony/api/constants"
)

type ErrorField struct {
	FieldPath       string
	Value           interface{}
	DetailedMessage string
}

func ValidateObjectName(name string, rootResource string) *ErrorField {
	if rootResource == "" {
		return &ErrorField{
			FieldPath:       "spec.rootResource",
			Value:           rootResource,
			DetailedMessage: "rootResource must be a non-empty string",
		}
	}

	if !strings.HasPrefix(name, rootResource) {
		return &ErrorField{
			FieldPath:       "metadata.name",
			Value:           name,
			DetailedMessage: "name must start with spec.rootResource",
		}
	}

	prefix := rootResource + constants.ResourceSeperator
	remaining := strings.TrimPrefix(name, prefix)

	if remaining == name {
		return &ErrorField{
			FieldPath:       "metadata.name",
			Value:           name,
			DetailedMessage: fmt.Sprintf("name should be in the format '<rootResource>%s<version>'", constants.ResourceSeperator),
		}

	}

	if strings.Contains(remaining, constants.ResourceSeperator) || strings.HasPrefix(remaining, "v-") {
		return &ErrorField{
			FieldPath:       "metadata.name",
			Value:           name,
			DetailedMessage: "name should be in the format <rootResource>-v-<version> where <version> does not contain '-v-' or starts with 'v-'",
		}
	}

	return nil
}

// Prototype for object lookup functions. Return value indicates if the object exists or not.
type ObjectLookupFunc func(objectName string, namespace string) (bool, interface{})

// Prototype for linked objects lookup functions.
// Return value includes  1) if objects exists or not and 2) the name of the first associated object.
type LinkedObjectLookupFunc func(objectName string, namespace string) (bool, string)

// rootResource is not in metadata now, pass in as a parameter
func (o *ObjectMeta) ValidateRootResource(rootResource string, lookupFunc ObjectLookupFunc) *ErrorField {
	if found, _ := lookupFunc(rootResource, o.Namespace); !found {
		return &ErrorField{
			FieldPath:       "spec.rootResource",
			Value:           rootResource,
			DetailedMessage: "rootResource must be a valid container",
		}
	}
	// ownerreferences check is only appliable to k8s
	return nil
}

func ConvertReferenceToObjectName(name string) string {
	if strings.Contains(name, constants.ReferenceSeparator) {
		name = strings.ReplaceAll(name, constants.ReferenceSeparator, constants.ResourceSeperator)
	}
	return name
}

func ConvertObjectNameToReference(name string) string {
	if strings.Contains(name, constants.ResourceSeperator) {
		name = strings.ReplaceAll(name, constants.ResourceSeperator, constants.ReferenceSeparator)
	}
	return name
}
