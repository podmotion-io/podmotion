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

// Package ci implements the CI matrix, flake database, and release gate logic
// for PodMotion. The canonical specification is ADR-0093 (formerly ADR-0079).
package ci

// Tier controls whether a matrix cell is release-blocking.
// +kubebuilder:validation:Enum=required;extended
type Tier string

const (
	TierRequired Tier = "required"
	TierExtended Tier = "extended"
)

// KernelEntry describes one kernel dimension in the CI matrix.
type KernelEntry struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version"`
	Ubuntu  string `yaml:"ubuntu,omitempty"`
	Debian  string `yaml:"debian,omitempty"`
	Tier    Tier   `yaml:"tier"`
}

// CNIEntry describes one CNI dimension in the CI matrix.
type CNIEntry struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version"`
	Tier    Tier   `yaml:"tier"`
}

// StorageEntry describes one storage backend dimension in the CI matrix.
type StorageEntry struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version,omitempty"`
	Tier    Tier   `yaml:"tier"`
}

// K8sVersionEntry describes one Kubernetes version dimension in the CI matrix.
type K8sVersionEntry struct {
	ID      string `yaml:"id"`
	Version string `yaml:"version,omitempty"`
	Ref     string `yaml:"ref"`
	Tier    Tier   `yaml:"tier"`
}

// CIMatrix is the parsed representation of ci/matrix.yaml.
type CIMatrix struct {
	SchemaVersion int               `yaml:"schema_version"`
	Kernels       []KernelEntry     `yaml:"kernels"`
	CNIs          []CNIEntry        `yaml:"cnis"`
	Storage       []StorageEntry    `yaml:"storage"`
	K8sVersions   []K8sVersionEntry `yaml:"k8s_versions"`
}

// MatrixCell is one runnable (kernel, cni, storage, k8s) tuple.
type MatrixCell struct {
	Kernel  KernelEntry
	CNI     CNIEntry
	Storage StorageEntry
	K8s     K8sVersionEntry
}

// IsReleaseBlocking returns true when the cell's failure must block release promotion.
// All four dimensions must be TierRequired for a cell to be release-blocking.
func (c MatrixCell) IsReleaseBlocking() bool {
	return c.Kernel.Tier == TierRequired &&
		c.CNI.Tier == TierRequired &&
		c.Storage.Tier == TierRequired &&
		c.K8s.Tier == TierRequired
}

// CellID returns the canonical "<kernel>/<cni>/<storage>/<k8s>" identifier.
func (c MatrixCell) CellID() string {
	return c.Kernel.ID + "/" + c.CNI.ID + "/" + c.Storage.ID + "/" + c.K8s.ID
}

// RequiredCells returns all (kernel, cni, storage, k8s) tuples where all four
// dimensions have Tier == TierRequired.
func (m *CIMatrix) RequiredCells() []MatrixCell {
	var cells []MatrixCell
	for _, k := range m.Kernels {
		if k.Tier != TierRequired {
			continue
		}
		for _, c := range m.CNIs {
			if c.Tier != TierRequired {
				continue
			}
			for _, s := range m.Storage {
				if s.Tier != TierRequired {
					continue
				}
				for _, v := range m.K8sVersions {
					if v.Tier != TierRequired {
						continue
					}
					cells = append(cells, MatrixCell{
						Kernel:  k,
						CNI:     c,
						Storage: s,
						K8s:     v,
					})
				}
			}
		}
	}
	return cells
}
