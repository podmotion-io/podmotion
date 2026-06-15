/*
Copyright YEAR.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package orchestration owns the end-to-end migration pipeline coordination.
//
// It is the arbiter between all domain agents: it sequences the phase gate
// protocol via PodMigration CR status, enforces cutover atomicity, manages
// migration concurrency at the cluster level, and owns the failure escalation
// and rollback decision logic.
//
// Phase gate sequence (time-ordered):
//  1. Admission (webhook)
//  2. Destination scheduling (scheduler plugin)
//  3. Pre-copy coordination (CRIU Engine Agent)
//  4. Storage pre-stage signal (Storage Agent ready)
//  5. eBPF bridge ready signal (Network Agent ready)
//  6. Final freeze authorization (all gates satisfied)
//  7. Checkpoint complete → transfer
//  8. IP handoff (Network Agent)
//  9. Restore authorization
//
// 10. Verification → Complete or → RollingBack
package orchestration
