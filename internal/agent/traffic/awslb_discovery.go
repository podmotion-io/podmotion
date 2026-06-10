/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package traffic

import (
	"context"
	"sync"
	"time"

	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

const discoveryCacheTTL = 30 * time.Second

type cachedEntry struct {
	arns      []string
	expiresAt time.Time
}

// TargetGroupDiscovery scans all target groups in the account/region to find which ones
// contain a given pod IP as a registered target.
//
// ADR-0027: annotation-only discovery is insufficient for externally managed LBs whose
// annotations may not be present on the pod. Full scan via DescribeTargetHealth is
// authoritative but expensive, so results are cached with a 30-second TTL.
type TargetGroupDiscovery struct {
	Client ELBV2API

	mu    sync.Mutex
	cache map[string]cachedEntry
}

// FindTargetGroupsForIP returns the ARNs of all target groups that have podIP as a
// registered target (regardless of health state). Results are cached for 30 seconds.
func (d *TargetGroupDiscovery) FindTargetGroupsForIP(ctx context.Context, podIP string) ([]string, error) {
	d.mu.Lock()
	if d.cache == nil {
		d.cache = make(map[string]cachedEntry)
	}
	if entry, ok := d.cache[podIP]; ok && time.Now().Before(entry.expiresAt) {
		d.mu.Unlock()
		return entry.arns, nil
	}
	d.mu.Unlock()

	arns, err := d.scanAll(ctx, podIP)
	if err != nil {
		return nil, err
	}

	d.mu.Lock()
	d.cache[podIP] = cachedEntry{arns: arns, expiresAt: time.Now().Add(discoveryCacheTTL)}
	d.mu.Unlock()

	return arns, nil
}

// scanAll iterates all target groups in the region and checks health to find ones
// containing podIP. Pagination is handled via NextMarker.
func (d *TargetGroupDiscovery) scanAll(ctx context.Context, podIP string) ([]string, error) {
	var matched []string
	var marker *string

	for {
		out, err := d.Client.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		for _, tg := range out.TargetGroups {
			if tg.TargetGroupArn == nil {
				continue
			}
			found, err := d.ipInTargetGroup(ctx, *tg.TargetGroupArn, podIP, tg.TargetType)
			if err != nil {
				// Non-fatal: skip TGs we cannot read (e.g. cross-account)
				continue
			}
			if found {
				matched = append(matched, *tg.TargetGroupArn)
			}
		}

		if out.NextMarker == nil {
			break
		}
		marker = out.NextMarker
	}

	return matched, nil
}

func (d *TargetGroupDiscovery) ipInTargetGroup(ctx context.Context, tgARN, podIP string, targetType elbv2types.TargetTypeEnum) (bool, error) {
	// Only IP-type target groups can contain pod IPs.
	if targetType != elbv2types.TargetTypeEnumIp {
		return false, nil
	}
	out, err := d.Client.DescribeTargetHealth(ctx, &elbv2.DescribeTargetHealthInput{
		TargetGroupArn: &tgARN,
	})
	if err != nil {
		return false, err
	}
	for _, desc := range out.TargetHealthDescriptions {
		if desc.Target != nil && desc.Target.Id != nil && *desc.Target.Id == podIP {
			return true, nil
		}
	}
	return false, nil
}
