/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import "encoding/json"

// jsonMarshal is an alias kept in a separate file so the main webhook file
// doesn't need a direct encoding/json import alongside the k8s runtime import.
var jsonMarshal = json.Marshal
