/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT license.
 * SPDX-License-Identifier: MIT
 */

package docker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/eclipse-symphony/symphony/api/pkg/apis/v1alpha1/model"
	"github.com/eclipse-symphony/symphony/api/pkg/apis/v1alpha1/utils"
	"github.com/eclipse-symphony/symphony/coa/pkg/apis/v1alpha2"
	"github.com/eclipse-symphony/symphony/coa/pkg/apis/v1alpha2/contexts"
	"github.com/eclipse-symphony/symphony/coa/pkg/apis/v1alpha2/observability"
	observ_utils "github.com/eclipse-symphony/symphony/coa/pkg/apis/v1alpha2/observability/utils"
	"github.com/eclipse-symphony/symphony/coa/pkg/apis/v1alpha2/providers"
	"github.com/eclipse-symphony/symphony/coa/pkg/logger"
)

const loggerName = "providers.target.docker"

var sLog = logger.NewLogger(loggerName)

type DockerTargetProviderConfig struct {
	Name string `json:"name"`
}

type DockerTargetProvider struct {
	Config  DockerTargetProviderConfig
	Context *contexts.ManagerContext
}

func DockerTargetProviderConfigFromMap(properties map[string]string) (DockerTargetProviderConfig, error) {
	ret := DockerTargetProviderConfig{}
	if v, ok := properties["name"]; ok {
		ret.Name = v
	}
	return ret, nil
}
func (d *DockerTargetProvider) InitWithMap(properties map[string]string) error {
	config, err := DockerTargetProviderConfigFromMap(properties)
	if err != nil {
		sLog.Errorf("  P (Docker Target): expected DockerTargetProviderConfigFromMap: %+v", err)
		return err
	}
	return d.Init(config)
}
func (s *DockerTargetProvider) SetContext(ctx *contexts.ManagerContext) {
	s.Context = ctx
}

func (d *DockerTargetProvider) Init(config providers.IProviderConfig) error {
	ctx, span := observability.StartSpan("Docker Target Provider", context.TODO(), &map[string]string{
		"method": "Init",
	})
	var err error = nil
	defer observ_utils.CloseSpanWithError(span, &err)
	defer observ_utils.EmitUserDiagnosticsLogs(ctx, &err)

	sLog.InfoCtx(ctx, "  P (Docker Target): Init()")

	// convert config to DockerTargetProviderConfig type
	dockerConfig, err := toDockerTargetProviderConfig(config)
	if err != nil {
		sLog.ErrorfCtx(ctx, "  P (Docker Target): expected DockerTargetProviderConfig: %+v", err)
		return err
	}

	d.Config = dockerConfig
	return nil
}
func toDockerTargetProviderConfig(config providers.IProviderConfig) (DockerTargetProviderConfig, error) {
	ret := DockerTargetProviderConfig{}
	data, err := json.Marshal(config)
	if err != nil {
		return ret, err
	}
	err = json.Unmarshal(data, &ret)
	return ret, err
}

func (i *DockerTargetProvider) Get(ctx context.Context, deployment model.DeploymentSpec, references []model.ComponentStep) ([]model.ComponentSpec, error) {
	ctx, span := observability.StartSpan("Docker Target Provider", ctx, &map[string]string{
		"method": "Get",
	})
	var err error = nil
	defer observ_utils.CloseSpanWithError(span, &err)
	defer observ_utils.EmitUserDiagnosticsLogs(ctx, &err)

	sLog.InfofCtx(ctx, "  P (Docker Target): getting artifacts: %s - %s", deployment.Instance.Spec.Scope, deployment.Instance.ObjectMeta.Name)

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to create docker client: %+v", err)
		return nil, err
	}

	ret := make([]model.ComponentSpec, 0)
	for _, component := range references {
		var info types.ContainerJSON
		info, err = cli.ContainerInspect(ctx, component.Component.Name)
		if err == nil {
			name := info.Name
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
			component := model.ComponentSpec{
				Name:       name,
				Properties: make(map[string]interface{}),
			}
			// container.args
			if len(info.Args) > 0 {
				argsData, _ := json.Marshal(info.Args)
				component.Properties["container.args"] = string(argsData)
			}
			// container.image
			component.Properties[model.ContainerImage] = info.Config.Image
			if info.HostConfig != nil {
				resources, _ := json.Marshal(info.HostConfig.Resources)
				component.Properties["container.resources"] = string(resources)
			}
			// container.ports
			if info.NetworkSettings != nil && len(info.NetworkSettings.Ports) > 0 {
				ports, _ := json.Marshal(info.NetworkSettings.Ports)
				component.Properties["container.ports"] = string(ports)
			}
			// container.cmd
			if len(info.Config.Cmd) > 0 {
				cmdData, _ := json.Marshal(info.Config.Cmd)
				component.Properties["container.commands"] = string(cmdData)
			}
			// container.volumeMounts
			if len(info.Mounts) > 0 {
				volumeData, _ := json.Marshal(info.Mounts)
				component.Properties["container.volumeMounts"] = string(volumeData)
			}
			// get environment varibles that are passed in by the reference
			env := info.Config.Env
			if len(env) > 0 {
				for _, e := range env {
					pair := strings.Split(e, "=")
					if len(pair) == 2 {
						for _, s := range references {
							if s.Component.Name == component.Name {
								for k, _ := range s.Component.Properties {
									if k == "env."+pair[0] {
										component.Properties[k] = pair[1]
									}
								}
							}
						}
					}
				}
			}
			sLog.InfofCtx(ctx, "  P (Docker Target): append component: %s", component.Name)
			ret = append(ret, component)
		} else {
			sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to get container info: %+v", err)
		}
	}

	return ret, nil
}

func (i *DockerTargetProvider) Apply(ctx context.Context, deployment model.DeploymentSpec, step model.DeploymentStep, isDryRun bool) (map[string]model.ComponentResultSpec, error) {
	ctx, span := observability.StartSpan("Docker Target Provider", ctx, &map[string]string{
		"method": "Apply",
	})
	var err error = nil
	defer observ_utils.CloseSpanWithError(span, &err)
	defer observ_utils.EmitUserDiagnosticsLogs(ctx, &err)

	sLog.InfofCtx(ctx, "  P (Docker Target): applying artifacts: %s - %s", deployment.Instance.Spec.Scope, deployment.Instance.ObjectMeta.Name)

	injections := &model.ValueInjections{
		InstanceId: deployment.Instance.ObjectMeta.Name,
		SolutionId: deployment.Instance.Spec.Solution,
		TargetId:   deployment.ActiveTarget,
	}

	components := step.GetComponents()
	err = i.GetValidationRule(ctx).Validate(components)
	if err != nil {
		sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to validate components: %+v", err)
		return nil, err
	}
	if isDryRun {
		sLog.DebugCtx(ctx, "  P (Docker Target): dryRun is enabled, skipping apply")
		err = nil
		return nil, nil
	}

	ret := step.PrepareResultMap()

	cli, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to create docker client: %+v", err)
		return ret, err
	}

	for _, component := range step.Components {
		if component.Action == model.ComponentUpdate {
			containerImage := model.ReadPropertyCompat(component.Component.Properties, model.ContainerImage, injections)
			resources := model.ReadPropertyCompat(component.Component.Properties, "container.resources", injections)
			if containerImage == "" {
				err = errors.New("component doesn't have container.image property")
				ret[component.Component.Name] = model.ComponentResultSpec{
					Status:  v1alpha2.UpdateFailed,
					Message: err.Error(),
				}
				sLog.ErrorfCtx(ctx, "  P (Docker Target): %+v", err)
				return ret, err
			}

			alreadyRunning := true
			_, err = cli.ContainerInspect(ctx, component.Component.Name)
			if err != nil { //TODO: check if the error is ErrNotFound
				alreadyRunning = false
			}

			reader, err := cli.ImagePull(ctx, containerImage, image.PullOptions{})
			if err != nil {
				sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to pull docker image: %+v", err)
				return ret, err
			}

			defer reader.Close()
			io.Copy(os.Stdout, reader)

			if alreadyRunning {
				err = cli.ContainerStop(ctx, component.Component.Name, container.StopOptions{})
				if err != nil {
					if !client.IsErrNotFound(err) {
						sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to stop a running container: %+v", err)
						return ret, err
					}
					sLog.DebugfCtx(ctx, "  P (Docker Target): container %s is not found", component.Component.Name)
				}
				err = cli.ContainerRemove(ctx, component.Component.Name, container.RemoveOptions{})
				if err != nil {
					ret[component.Component.Name] = model.ComponentResultSpec{
						Status:  v1alpha2.UpdateFailed,
						Message: err.Error(),
					}
					sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to remove existing container: %+v", err)
					return ret, err
				}
			}

			// prepare environment variables
			env := make([]string, 0)
			for k, v := range component.Component.Properties {
				if strings.HasPrefix(k, "env.") {
					env = append(env, strings.TrimPrefix(k, "env.")+"="+utils.FormatAsString(v))
				}
			}

			containerConfig := container.Config{
				Image: containerImage,
				Env:   env,
			}
			var hostConfig *container.HostConfig
			if resources != "" {
				var resourceSpec container.Resources
				err = json.Unmarshal([]byte(resources), &resourceSpec)
				if err != nil {
					ret[component.Component.Name] = model.ComponentResultSpec{
						Status:  v1alpha2.UpdateFailed,
						Message: err.Error(),
					}
					sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to read container resource settings: %+v", err)
					return ret, err
				}
				hostConfig = &container.HostConfig{
					Resources: resourceSpec,
				}
			}
			var containerResponse container.CreateResponse
			sLog.InfofCtx(ctx, "  P (Docker Target): create container: %s", component.Component.Name)
			containerResponse, err = cli.ContainerCreate(ctx, &containerConfig, hostConfig, nil, nil, component.Component.Name)
			if err != nil {
				ret[component.Component.Name] = model.ComponentResultSpec{
					Status:  v1alpha2.UpdateFailed,
					Message: err.Error(),
				}
				sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to create container: %+v", err)
				return ret, err
			}

			sLog.InfofCtx(ctx, "  P (Docker Target): start container: %s", component.Component.Name)
			if err = cli.ContainerStart(ctx, containerResponse.ID, container.StartOptions{}); err != nil {
				ret[component.Component.Name] = model.ComponentResultSpec{
					Status:  v1alpha2.UpdateFailed,
					Message: err.Error(),
				}
				sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to start container: %+v", err)
				return ret, err
			}
			ret[component.Component.Name] = model.ComponentResultSpec{
				Status:  v1alpha2.Updated,
				Message: "",
			}
		} else {
			sLog.InfofCtx(ctx, "  P (Docker Target): stop container: %s", component.Component.Name)
			err = cli.ContainerStop(ctx, component.Component.Name, container.StopOptions{})
			if err != nil {
				if !client.IsErrNotFound(err) {
					sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to stop a running container: %+v", err)
					return ret, err
				}
				sLog.DebugfCtx(ctx, "  P (Docker Target): container %s is not found", component.Component.Name)
			}

			sLog.InfofCtx(ctx, "  P (Docker Target): remove container: %s", component.Component.Name)
			err = cli.ContainerRemove(ctx, component.Component.Name, container.RemoveOptions{})
			if err != nil {
				if !client.IsErrNotFound(err) {
					sLog.ErrorfCtx(ctx, "  P (Docker Target): failed to remove existing container: %+v", err)
					return ret, err
				}
				sLog.DebugfCtx(ctx, "  P (Docker Target): container %s is not found", component.Component.Name)
			}
			ret[component.Component.Name] = model.ComponentResultSpec{
				Status:  v1alpha2.Deleted,
				Message: "",
			}
		}
	}
	return ret, nil
}

func (*DockerTargetProvider) GetValidationRule(ctx context.Context) model.ValidationRule {
	return model.ValidationRule{
		AllowSidecar: false,
		ComponentValidationRule: model.ComponentValidationRule{
			RequiredProperties:    []string{model.ContainerImage},
			OptionalProperties:    []string{"container.resources"},
			RequiredComponentType: "",
			RequiredMetadata:      []string{},
			OptionalMetadata:      []string{},
			ChangeDetectionProperties: []model.PropertyDesc{
				{Name: model.ContainerImage, IgnoreCase: false, SkipIfMissing: false},
				{Name: "container.ports", IgnoreCase: false, SkipIfMissing: true},
				{Name: "container.resources", IgnoreCase: false, SkipIfMissing: true},
			},
		},
	}
}
