/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package model

import (
	"fmt"
	"strings"
)

// Check Campaign Container existence
var CampaignContainerLookupFunc ObjectLookupFunc

// Check Activations associated with the Campaign
var CampaignActivationsLookupFunc LinkedObjectLookupFunc

func SetCampaignContainerLookupFunc(f ObjectLookupFunc) {
	CampaignContainerLookupFunc = f
}

func SetCampaignActivationsLookupFunc(f LinkedObjectLookupFunc) {
	CampaignActivationsLookupFunc = f
}

func (c *CampaignState) ValidateCreate() []ErrorField {
	errorFields := []ErrorField{}
	// validate naming convension
	if err := ValidateObjectName(c.ObjectMeta.Name, c.Spec.RootResource); err != nil {
		errorFields = append(errorFields, *err)
	}
	// validate rootResource
	if err := c.ObjectMeta.ValidateRootResource(c.Spec.RootResource, CampaignContainerLookupFunc); err != nil {
		errorFields = append(errorFields, *err)
	}
	// validate firstStage
	if err := c.ValidateFirstStage(); err != nil {
		errorFields = append(errorFields, *err)
	}
	// validate StageSelector
	if err := c.ValidateStages(); err != nil {
		errorFields = append(errorFields, *err)
	}
	return errorFields
}

func (c *CampaignState) ValidateUpdate(oldc *CampaignState) []ErrorField {
	errorFields := []ErrorField{}
	// validate first stage if it is changed
	if c.Spec.FirstStage != oldc.Spec.FirstStage {
		if err := c.ValidateFirstStage(); err != nil {
			errorFields = append(errorFields, *err)
		}
	}
	// validate rootResource is not changed
	if c.Spec.RootResource != oldc.Spec.RootResource {
		errorFields = append(errorFields, ErrorField{
			FieldPath:       "spec.rootResource",
			Value:           c.Spec.RootResource,
			DetailedMessage: "rootResource is immutable",
		})
	}
	// validate StageSelector
	if err := c.ValidateStages(); err != nil {
		errorFields = append(errorFields, *err)
	}
	// validate no running activations
	if err := c.ValidateRunningActivation(); err != nil {
		errorFields = append(errorFields, *err)
	}
	return errorFields
}

func (c *CampaignState) ValidateDelete() []ErrorField {
	errorFields := []ErrorField{}
	// validate no running activations
	if err := c.ValidateRunningActivation(); err != nil {
		errorFields = append(errorFields, *err)
	}
	return errorFields
}

func (c *CampaignState) ValidateFirstStage() *ErrorField {
	isValid := false
	if c.Spec.FirstStage == "" {
		if c.Spec.Stages == nil || len(c.Spec.Stages) == 0 {
			isValid = true
		}
	}
	for _, stage := range c.Spec.Stages {
		if stage.Name == c.Spec.FirstStage {
			isValid = true
		}
	}
	if !isValid {
		return &ErrorField{
			FieldPath:       "spec.firstStage",
			Value:           c.Spec.FirstStage,
			DetailedMessage: "firstStage must be one of the stages in the stages list",
		}
	} else {
		return nil
	}
}

func (c *CampaignState) ValidateStages() *ErrorField {
	stages := make(map[string]struct{}, 0)
	for _, stage := range c.Spec.Stages {
		stages[stage.Name] = struct{}{}
	}
	for _, stage := range c.Spec.Stages {
		if !strings.Contains(stage.StageSelector, "$") && stage.StageSelector != "" {
			if _, ok := stages[stage.StageSelector]; !ok {
				return &ErrorField{
					FieldPath:       fmt.Sprintf("spec.stages.%s.stageSelector", stage.Name),
					Value:           stage.StageSelector,
					DetailedMessage: "stageSelector must be one of the stages in the stages list",
				}
			}
		}
	}
	return nil
}

func (c *CampaignState) ValidateRunningActivation() *ErrorField {
	if CampaignActivationsLookupFunc != nil {
		if found, _ := CampaignActivationsLookupFunc(c.ObjectMeta.Name, c.ObjectMeta.Namespace); found {
			return &ErrorField{
				FieldPath:       "metadata.name",
				Value:           c.ObjectMeta.Name,
				DetailedMessage: "Campaign has one or more running activations. Update or Deletion is not allowed",
			}
		}
	}
	return nil
}
