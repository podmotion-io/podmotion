/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"fmt"
	"net/http"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	pmv1 "github.com/podmotion-io/podmotion/api/v1alpha1"
)

// MigrationCheckpointValidator validates MigrationCheckpoint objects.
// Key invariant (ADR-0034): when the owning PodMigration targets a remote cluster,
// TransferMode MUST be Registry. DirectP2P requires a routable gRPC path between
// nodes which cannot be assumed across cluster boundaries.
type MigrationCheckpointValidator struct {
	client  client.Client
	decoder admission.Decoder
}

// SetupWithManager registers the webhook.
func (v *MigrationCheckpointValidator) SetupWithManager(mgr ctrl.Manager) error {
	v.client = mgr.GetClient()
	v.decoder = admission.NewDecoder(mgr.GetScheme())
	mgr.GetWebhookServer().Register(
		"/validate-podmotion-io-v1alpha1-migrationcheckpoint",
		&admission.Webhook{Handler: v},
	)
	return nil
}

// Handle implements admission.Handler.
func (v *MigrationCheckpointValidator) Handle(ctx context.Context, req admission.Request) admission.Response {
	mcp := &pmv1.MigrationCheckpoint{}
	if err := v.decoder.Decode(req, mcp); err != nil {
		return admission.Errored(http.StatusBadRequest, err)
	}

	if errs := v.validate(ctx, mcp); len(errs) > 0 {
		return admission.Denied(errs.ToAggregate().Error())
	}
	return admission.Allowed("")
}

func (v *MigrationCheckpointValidator) validate(ctx context.Context, mcp *pmv1.MigrationCheckpoint) field.ErrorList {
	var allErrs field.ErrorList
	spec := field.NewPath("spec")

	// ADR-0034: DirectP2P is blocked for cross-cluster migrations.
	// Look up the owning PodMigration to determine if this is cross-cluster.
	if mcp.Spec.PodMigrationRef != "" {
		pm, err := v.getPodMigration(ctx, mcp.Namespace, mcp.Spec.PodMigrationRef)
		if err != nil && !apierrors.IsNotFound(err) {
			allErrs = append(allErrs, field.InternalError(spec.Child("podMigrationRef"), err))
		}
		if pm != nil && pm.Spec.DestinationCluster != "" {
			if mcp.Spec.TransferMode == pmv1.CheckpointTransferModeDirectP2P {
				allErrs = append(allErrs, field.Forbidden(spec.Child("transferMode"),
					fmt.Sprintf("DirectP2P transfer mode is not supported for cross-cluster migrations (destinationCluster=%q); use Registry mode — the OCI image is the WAN transfer medium (ADR-0034)",
						pm.Spec.DestinationCluster)))
			}
		}
	}

	return allErrs
}

func (v *MigrationCheckpointValidator) getPodMigration(ctx context.Context, namespace, name string) (*pmv1.PodMigration, error) {
	pm := &pmv1.PodMigration{}
	err := v.client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, pm)
	if apierrors.IsNotFound(err) {
		return nil, err
	}
	return pm, err
}
