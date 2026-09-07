/*
Copyright 2026 PodMotion Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

// adr0423_sole_writer_structural_test.go implements ADR-0423 V2a/V5b: rather than trusting a
// prose enumeration of callers (which failed twice — round 2's five reconcileRollingBack exits,
// round 3's implicit two-caller enumeration), these tests mechanically scan the ENTIRE
// internal/controller package source (excluding _test.go files) for every site of the shape
// `Status.Phase = pmv1.MigrationPhaseFailed`/`MigrationPhaseRollingBack` or a call
// `transitionTo(..., pmv1.MigrationPhaseFailed)`/`MigrationPhaseRollingBack`, and fail unless
// there is EXACTLY ONE such site, textually inside the one function the ADR names as the sole
// writer. This converts "sole writer" from a claim re-verified by re-reading the source every
// review round into an invariant a future violation cannot silently introduce — the test fails
// the moment a new write site is written, not the next time a reviewer happens to notice it.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// phaseWriteSite records one occurrence of a Phase= write matching a target constant, plus the
// name of the top-level function it was found inside.
type phaseWriteSite struct {
	file string
	line int
	fn   string
}

// thisPackageDir returns the directory containing this test file — i.e. internal/controller.
func thisPackageDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed — cannot locate package directory for structural scan")
	}
	return filepath.Dir(file)
}

// isPMV1PhaseConst reports whether e is the selector expression `pmv1.<constName>`.
func isPMV1PhaseConst(e ast.Expr, constName string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != constName {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "pmv1"
}

// isDotStatusPhase reports whether e is a selector chain ending in `.Status.Phase`
// (i.e. <anything>.Status.Phase).
func isDotStatusPhase(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Phase" {
		return false
	}
	base, ok := sel.X.(*ast.SelectorExpr)
	return ok && base.Sel.Name == "Status"
}

// scanPhaseWriteSites parses every non-test .go file in dir and returns every site assigning the
// given pmv1 phase constant to a `.Status.Phase` field, or passing it as the final argument to a
// call named `transitionTo`. Each site records the top-level function it was found inside.
func scanPhaseWriteSites(t *testing.T, dir, constName string) []phaseWriteSite {
	t.Helper()
	fset := token.NewFileSet()
	filter := func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }
	pkgs, err := parser.ParseDir(fset, dir, filter, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}

	var sites []phaseWriteSite
	for _, pkg := range pkgs {
		for fname, file := range pkg.Files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				fnName := fd.Name.Name
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					switch stmt := n.(type) {
					case *ast.AssignStmt:
						if stmt.Tok == token.ASSIGN && len(stmt.Lhs) == 1 && len(stmt.Rhs) == 1 &&
							isDotStatusPhase(stmt.Lhs[0]) && isPMV1PhaseConst(stmt.Rhs[0], constName) {
							pos := fset.Position(stmt.Pos())
							sites = append(sites, phaseWriteSite{file: filepath.Base(fname), line: pos.Line, fn: fnName})
						}
					case *ast.CallExpr:
						if sel, ok := stmt.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "transitionTo" &&
							len(stmt.Args) > 0 && isPMV1PhaseConst(stmt.Args[len(stmt.Args)-1], constName) {
							pos := fset.Position(stmt.Pos())
							sites = append(sites, phaseWriteSite{file: filepath.Base(fname), line: pos.Line, fn: fnName})
						}
					}
					return true
				})
			}
		}
	}
	return sites
}

// TestADR0423_StructuralSoleWriter_PhaseFailed is V2a: the sole writer of Phase=Failed in
// internal/controller must be finalizeFailed, and no other site may exist.
func TestADR0423_StructuralSoleWriter_PhaseFailed(t *testing.T) {
	sites := scanPhaseWriteSites(t, thisPackageDir(t), "MigrationPhaseFailed")
	if len(sites) != 1 {
		t.Fatalf("expected exactly 1 Phase=Failed write site in internal/controller, found %d: %+v", len(sites), sites)
	}
	if sites[0].fn != "finalizeFailed" {
		t.Fatalf("the sole Phase=Failed write site must be inside finalizeFailed, found in %s (%s:%d)",
			sites[0].fn, sites[0].file, sites[0].line)
	}
}

// TestADR0423_StructuralSoleWriter_PhaseRollingBack is V5b (Gap 2d): the sole writer of
// Phase=RollingBack in internal/controller must be enterRollingBack, and no other site may exist.
func TestADR0423_StructuralSoleWriter_PhaseRollingBack(t *testing.T) {
	sites := scanPhaseWriteSites(t, thisPackageDir(t), "MigrationPhaseRollingBack")
	if len(sites) != 1 {
		t.Fatalf("expected exactly 1 Phase=RollingBack write site in internal/controller, found %d: %+v", len(sites), sites)
	}
	if sites[0].fn != "enterRollingBack" {
		t.Fatalf("the sole Phase=RollingBack write site must be inside enterRollingBack, found in %s (%s:%d)",
			sites[0].fn, sites[0].file, sites[0].line)
	}
}

// TestADR0423_StructuralSoleWriter_NoPhaseAssignmentInAgentStorage is V5b's companion
// belt-and-suspenders check: after the RollbackEnterer conversion, internal/agent/storage must
// contain NO `Status.Phase =` assignment of any kind (not just RollingBack) — the direct field
// write in fencing.go's initiateRollback is deleted, not merely wrapped.
func TestADR0423_StructuralSoleWriter_NoPhaseAssignmentInAgentStorage(t *testing.T) {
	dir := filepath.Join(thisPackageDir(t), "..", "agent", "storage")
	fset := token.NewFileSet()
	filter := func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }
	pkgs, err := parser.ParseDir(fset, dir, filter, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}

	var hits []phaseWriteSite
	for _, pkg := range pkgs {
		for fname, file := range pkg.Files {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				fnName := fd.Name.Name
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					stmt, ok := n.(*ast.AssignStmt)
					if !ok || stmt.Tok != token.ASSIGN || len(stmt.Lhs) != 1 {
						return true
					}
					if isDotStatusPhase(stmt.Lhs[0]) {
						pos := fset.Position(stmt.Pos())
						hits = append(hits, phaseWriteSite{file: filepath.Base(fname), line: pos.Line, fn: fnName})
					}
					return true
				})
			}
		}
	}
	if len(hits) != 0 {
		t.Fatalf("expected zero Status.Phase= assignments in internal/agent/storage (ADR-0423 RollbackEnterer conversion), found %d: %+v", len(hits), hits)
	}
}
