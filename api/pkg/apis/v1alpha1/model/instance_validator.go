/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package model

var UniqueNameInstanceLookupFunc ObjectLookupFunc
var SolutionLookupFunc ObjectLookupFunc
var TargetLookupFunc ObjectLookupFunc

func (c *InstanceState) ValidateCreate() []ErrorField {
	errorFields := []ErrorField{}
	if err := c.ValidateUniqueName(); err != nil {
		errorFields = append(errorFields, *err)
	}
	if err := c.ValidateSolutionExist(); err != nil {
		errorFields = append(errorFields, *err)
	}
	// if err := c.ValidateTargetExist(); err != nil {
	// 	errorFields = append(errorFields, *err)
	// }
	if err := c.ValidateTargetValid(); err != nil {
		errorFields = append(errorFields, *err)
	}
	return errorFields
}

func (c *InstanceState) ValidateUpdate(oldc *InstanceState) []ErrorField {
	errorFields := []ErrorField{}
	if c.Spec.DisplayName != oldc.Spec.DisplayName {
		if err := c.ValidateUniqueName(); err != nil {
			errorFields = append(errorFields, *err)
		}
	}
	if c.Spec.Solution != oldc.Spec.Solution {
		if err := c.ValidateSolutionExist(); err != nil {
			errorFields = append(errorFields, *err)
		}
	}
	if c.Spec.Target.Name != oldc.Spec.Target.Name && c.Spec.Target.Name != "" {
		if err := c.ValidateTargetExist(); err != nil {
			errorFields = append(errorFields, *err)
		}
	}
	if err := c.ValidateTargetValid(); err != nil {
		errorFields = append(errorFields, *err)
	}
	return errorFields
}

func (c *InstanceState) ValidateDelete() []ErrorField {
	return []ErrorField{}
}

func (c *InstanceState) ValidateUniqueName() *ErrorField {
	exist, _ := UniqueNameInstanceLookupFunc(c.Spec.DisplayName, c.ObjectMeta.Namespace)
	if exist {
		return &ErrorField{
			FieldPath:       "spec.displayName",
			Value:           c.Spec.DisplayName,
			DetailedMessage: "instance displayName must be unique",
		}
	}
	return nil
}

func (c *InstanceState) ValidateSolutionExist() *ErrorField {
	exist, _ := SolutionLookupFunc(ConvertReferenceToObjectName(c.Spec.Solution), c.ObjectMeta.Namespace)
	if !exist {
		return &ErrorField{
			FieldPath:       "spec.solution",
			Value:           c.Spec.Solution,
			DetailedMessage: "solution does not exist",
		}
	}
	return nil
}

func (c *InstanceState) ValidateTargetExist() *ErrorField {
	exist, _ := TargetLookupFunc(c.Spec.Solution, c.ObjectMeta.Namespace)
	if !exist {
		return &ErrorField{
			FieldPath:       "spec.target.name",
			Value:           c.Spec.Target.Name,
			DetailedMessage: "target does not exist",
		}

	}
	return nil
}

func (c *InstanceState) ValidateTargetValid() *ErrorField {
	if c.Spec.Target.Name == "" && (c.Spec.Target.Selector == nil || len(c.Spec.Target.Selector) == 0) {
		return &ErrorField{
			FieldPath:       "spec.target",
			Value:           c.Spec.Target,
			DetailedMessage: "target must have either name or valid selector",
		}
	}
	return nil
}
