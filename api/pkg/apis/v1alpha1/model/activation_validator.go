/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package model

import (
	"encoding/json"
	"strings"
)

// Check Campaign existence
var CampaignLookupFunc ObjectLookupFunc

func SetCampaignLookupFunc(f ObjectLookupFunc) {
	CampaignLookupFunc = f
}

func (c *ActivationState) ValidateCreate() []ErrorField {
	errorFields := []ErrorField{}
	// validate campaign
	if err := c.ValidateCampaignAndStage(); err != nil {
		errorFields = append(errorFields, *err)
	}

	return errorFields
}

func (c *ActivationState) ValidateUpdate(oldc *ActivationState) []ErrorField {
	errorFields := []ErrorField{}
	// validate spec is immutable
	if equal, _ := c.Spec.DeepEquals(oldc.Spec); !equal {
		errorFields = append(errorFields, ErrorField{
			FieldPath:       "spec",
			Value:           c.Spec,
			DetailedMessage: "spec is immutable",
		})
	}

	return errorFields
}

func (c *ActivationState) ValidateCampaignAndStage() *ErrorField {
	campaignName := ConvertReferenceToObjectName(c.Spec.Campaign)
	found, Campaign := CampaignLookupFunc(campaignName, c.ObjectMeta.Namespace)
	if !found {
		return &ErrorField{
			FieldPath:       "spec.campaign",
			Value:           campaignName,
			DetailedMessage: "campaign reference must be a valid Campaign object in the same namespace",
		}
	}
	if c.Spec.Stage == "" || strings.Contains(c.Spec.Stage, "$") {
		// Skip validation if stage is not provided or is an expression
		return nil
	}

	marshalResult, err := json.Marshal(Campaign)
	if err != nil {
		return nil
	}
	var campaign CampaignState
	err = json.Unmarshal(marshalResult, &campaign)
	if err != nil {
		return nil
	}
	for _, stage := range campaign.Spec.Stages {
		if stage.Name == c.Spec.Stage {
			return nil
		}
	}
	return &ErrorField{
		FieldPath:       "spec.stage",
		Value:           c.Spec.Stage,
		DetailedMessage: "spec.stage must be a valid stage in the campaign",
	}
}
