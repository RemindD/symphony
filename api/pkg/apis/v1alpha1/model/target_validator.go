/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package model

// Check Activations associated with the Campaign
var TargetInstanceLookupFunc LinkedObjectLookupFunc

var UniqueNameTargetLookupFunc ObjectLookupFunc

func (t *TargetState) ValidateCreate() []ErrorField {
	return []ErrorField{}
}

func (t *TargetState) ValidateUpdate() []ErrorField {
	return []ErrorField{}
}

func (t *TargetState) ValidateDelete() []ErrorField {
	errorFields := []ErrorField{}
	if err := t.ValidateNoInstance(); err != nil {
		errorFields = append(errorFields, *err)
	}
	return errorFields
}
func (t *TargetState) ValidateUniqueName() *ErrorField {
	exist, _ := UniqueNameTargetLookupFunc(t.Spec.DisplayName, t.ObjectMeta.Namespace)
	if exist {
		return &ErrorField{
			FieldPath:       "spec.displayName",
			Value:           t.Spec.DisplayName,
			DetailedMessage: "target displayName must be unique",
		}
	}
	return nil
}
func (t *TargetState) ValidateNoInstance() *ErrorField {
	found, _ := TargetInstanceLookupFunc(t.ObjectMeta.Name, t.ObjectMeta.Namespace)
	if found {
		return &ErrorField{
			FieldPath:       "metadata.name",
			Value:           t.ObjectMeta.Name,
			DetailedMessage: "Target has one or more associated instances. Deletion is not allowed.",
		}
	}
	return nil
}
