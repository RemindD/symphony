/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"gopls-workspace/constants"

	"github.com/eclipse-symphony/symphony/api/pkg/apis/v1alpha1/model"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var targetKeyRegex = regexp.MustCompile(`^targets\.[^.]+\.[^.]+`)

func IsComponentKey(key string) bool {
	return targetKeyRegex.MatchString(key)
}

func HashObjects(deploymentResources DeploymentResources) string {
	hasher := md5.New()

	// Sort the targets by name
	sort.Slice(deploymentResources.TargetCandidates, func(i, j int) bool {
		return deploymentResources.TargetCandidates[i].GetName() < deploymentResources.TargetCandidates[j].GetName()
	})

	// Add the solution and instance to the hasher
	writeObjectHash(hasher, &deploymentResources.Solution)
	writeObjectHash(hasher, &deploymentResources.Instance)

	// Add the sorted targets to the hasher
	for _, target := range deploymentResources.TargetCandidates {
		writeObjectHash(hasher, &target)
	}

	// Get the final hash result
	return hex.EncodeToString(hasher.Sum(nil))
}

func writeObjectHash(writer io.Writer, object client.Object) {
	fmt.Fprintf(writer, "<%s:%s:%s:%d>",
		object.GetName(),
		object.GetObjectKind().GroupVersionKind().Kind,
		object.GetAnnotations()[constants.AzureOperationIdKey],
		object.GetGeneration(),
	)
}

func ConvertErrorFieldsToK8sError(ErrorFields []model.ErrorField) field.ErrorList {
	var allErrs field.ErrorList
	for _, errorField := range ErrorFields {
		pathArray := strings.Split(errorField.FieldPath, ".")
		errorPath := field.NewPath(pathArray[0])
		for _, path := range pathArray[1:] {
			errorPath = errorPath.Child(path)
		}
		allErrs = append(allErrs, field.Invalid(errorPath, errorField.Value, errorField.DetailedMessage))
	}
	return allErrs
}
