/*

	MIT License

	Copyright (c) Microsoft Corporation.

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE

*/

package v1

import (
	"context"
	"encoding/json"

	"github.com/azure/symphony/api/pkg/apis/v1alpha1/utils"
	"github.com/azure/symphony/coa/pkg/apis/v1alpha2"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// log is for logging in this package.
var cataloglog = logf.Log.WithName("catalog-resource")
var myCatalogClient client.Client

func (r *Catalog) SetupWebhookWithManager(mgr ctrl.Manager) error {
	myCatalogClient = mgr.GetClient()
	mgr.GetFieldIndexer().IndexField(context.Background(), &Catalog{}, ".spec.name", func(rawObj client.Object) []string {
		target := rawObj.(*Catalog)
		return []string{target.Name}
	})
	return ctrl.NewWebhookManagedBy(mgr).
		For(r).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

//+kubebuilder:webhook:path=/mutate-federation-symphony-v1-catalog,mutating=true,failurePolicy=fail,sideEffects=None,groups=federation.symphony,resources=catalogs,verbs=create;update,versions=v1,name=mcatalog.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &Catalog{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (r *Catalog) Default() {
	cataloglog.Info("default", "name", r.Name)
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.

//+kubebuilder:webhook:path=/validate-federation-symphony-v1-catalog,mutating=false,failurePolicy=fail,sideEffects=None,groups=federation.symphony,resources=catalogs,verbs=create;update,versions=v1,name=vcatalog.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &Catalog{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (r *Catalog) ValidateCreate() error {
	cataloglog.Info("validate create", "name", r.Name)

	return r.validateCreateCatalog()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (r *Catalog) ValidateUpdate(old runtime.Object) error {
	cataloglog.Info("validate update", "name", r.Name)

	return r.validateUpdateCatalog()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (r *Catalog) ValidateDelete() error {
	cataloglog.Info("validate delete", "name", r.Name)

	return nil
}

func (r *Catalog) validateCreateCatalog() error {
	return r.checkSchema()
}

func (r *Catalog) checkSchema() error {
	if schemaName, ok := r.Spec.Metadata["schema"]; ok {
		var catalogs CatalogList
		err := myCatalogClient.List(context.Background(), &catalogs, client.InNamespace(r.Namespace), client.MatchingFields{".spec.name": schemaName})
		if err != nil || len(catalogs.Items) == 0 {
			return err
		}

		jData, _ := json.Marshal(catalogs.Items[0].Spec.Properties)
		var properties map[string]interface{}
		err = json.Unmarshal(jData, &properties)
		if err != nil {
			return v1alpha2.NewCOAError(err, "invalid schema", v1alpha2.ValidateFailed)
		}
		if spec, ok := properties["spec"]; ok {
			var schemaObj utils.Schema
			jData, _ := json.Marshal(spec)
			err := json.Unmarshal(jData, &schemaObj)
			if err != nil {
				return v1alpha2.NewCOAError(err, "invalid schema", v1alpha2.ValidateFailed)
			}
			jData, _ = json.Marshal(r.Spec.Properties)
			var properties map[string]interface{}
			err = json.Unmarshal(jData, &properties)
			if err != nil {
				return v1alpha2.NewCOAError(err, "invalid properties", v1alpha2.ValidateFailed)
			}
			result, err := schemaObj.CheckProperties(properties, nil)
			if err != nil {
				return v1alpha2.NewCOAError(err, "invalid properties", v1alpha2.ValidateFailed)
			}
			if !result.Valid {
				return v1alpha2.NewCOAError(err, "invalid properties", v1alpha2.ValidateFailed)
			}
		}
	}
	return nil
}
func (r *Catalog) validateUpdateCatalog() error {
	return r.checkSchema()
}