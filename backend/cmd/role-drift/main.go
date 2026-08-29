// Command role-drift reports every way registry's own authorization tables
// disagree with the identity tables they were derived from, and exits non-zero
// while any row is unreconciled.
//
// IT IS THE GATE ON THE READ CUTOVER (sethbacon/terraform-suite-identity#206).
// The rule is the one `bind-secrets verify` established in this estate: a clean
// exit is what permits the next step, and nothing else does.
//
//	role-drift            # compare, print, exit 0 only if the two copies agree
//	role-drift -v         # also print what was compared when there is no drift
//
// Exit codes, so a pipeline can tell the three outcomes apart:
//
//	0  the two copies agree
//	1  they disagree; every disagreement is printed
//	2  the comparison could not be made (unreachable table, bad config, ...)
//
// 2 is separate from 1 DELIBERATELY. "Could not check" must never be spelled
// the same way as "checked and found nothing", or a misconfigured run gates the
// cutover open.
//
// It reads configuration exactly as cmd/server does -- the same config file and
// the same TFR_IDENTITY_* environment -- because which schema and which
// database hold the live identity rows is chosen at process start, and a check
// that decided that for itself would be comparing something other than what the
// server compares.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/terraform-registry/terraform-registry/internal/config"
	"github.com/terraform-registry/terraform-registry/internal/db"
	"github.com/terraform-registry/terraform-registry/internal/db/repositories"
)

// exit codes, named so the switch below reads as the contract above.
const (
	exitClean       = 0
	exitDrift       = 1
	exitIndetermina = 2
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "", "path to the registry config file (same file cmd/server reads)")
	verbose := flag.Bool("v", false, "print what was compared even when there is no drift")
	timeout := flag.Duration("timeout", 5*time.Minute, "maximum time to spend comparing")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "role-drift: could not load configuration: %v\n", err)
		return exitIndetermina
	}

	registryDB, err := db.Connect(cfg.Database.GetDSN(), cfg.Database.MaxConnections, cfg.Database.MinIdleConnections)
	if err != nil {
		fmt.Fprintf(os.Stderr, "role-drift: could not connect to the registry database: %v\n", err)
		return exitIndetermina
	}
	defer func() { _ = registryDB.Close() }()

	identityDB, closeIdentity, err := connectIdentity(cfg, registryDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "role-drift: could not connect to the identity database: %v\n", err)
		return exitIndetermina
	}
	defer closeIdentity()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	report, err := repositories.CheckMemberRoleDrift(ctx, identityDB, registryDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "role-drift: could not compare the two copies: %v\n", err)
		return exitIndetermina
	}

	// The group-mapping half (terraform-suite-identity#206 phase 2, migration
	// 000059) rides the same verb: it compares the same two connections, it
	// gates the same program's next step, and a deployment that would run one
	// check and not the other is exactly how half a dual-write ships.
	groupReport, err := repositories.CheckGroupMappingDrift(ctx, identityDB, registryDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "role-drift: could not compare the group-mapping copies: %v\n", err)
		return exitIndetermina
	}

	if report.Clean() && groupReport.Clean() {
		if *verbose {
			printScope(report)
			printGroupScope(groupReport)
		}
		fmt.Printf("role-drift: no drift (%d membership(s), %d role template(s), %d group mapping(s) compared)\n",
			report.SourceMemberships, report.SourceRoleTemplates, groupReport.SourceMappings)
		return exitClean
	}

	if !report.Clean() {
		fmt.Fprintf(os.Stderr, "role-drift: %d disagreement(s) between registry's own authorization tables "+
			"and the identity tables they mirror\n\n", len(report.Rows))
		for _, row := range report.Rows {
			fmt.Fprintln(os.Stderr, "  "+row.String())
		}
		fmt.Fprintln(os.Stderr)
	}
	if !groupReport.Clean() {
		fmt.Fprintf(os.Stderr, "role-drift: %d disagreement(s) between registry's own group_mappings table "+
			"and the oidc_config.extra_config lists it mirrors\n\n", len(groupReport.Rows))
		for _, row := range groupReport.Rows {
			fmt.Fprintln(os.Stderr, "  "+row.String())
		}
		fmt.Fprintln(os.Stderr)
	}
	printScope(report)
	printGroupScope(groupReport)
	fmt.Fprintln(os.Stderr, "\nRestarting the backend re-derives registry's tables from the identity source and "+
		"repairs anything a transient write failure left behind; re-run this afterwards. Rows that persist are "+
		"described in docs/identity-schema.md, which also says which ones an operator must decide rather than repair.")
	return exitDrift
}

// printScope states what was compared. A gate that reports "no drift" without
// saying how many rows it looked at cannot be told apart from a gate that
// looked at nothing, and this estate has certified an empty universe before.
func printScope(report repositories.DriftReport) {
	fmt.Fprintf(os.Stderr, "compared: %d source membership(s) vs %d mirrored, %d source role template(s) vs %d mirrored\n",
		report.SourceMemberships, report.MirroredMemberships,
		report.SourceRoleTemplates, report.MirroredRoleTemplates)
}

// printGroupScope states what the group-mapping comparison looked at, for the
// same reason printScope exists.
func printGroupScope(report repositories.GroupMappingDriftReport) {
	fmt.Fprintf(os.Stderr, "compared: %d source group mapping(s) across %d oidc config(s) vs %d mirrored"+
		" (%d config(s) with unparseable extra_config)\n",
		report.SourceMappings, report.SourceConfigs, report.MirroredMappings, report.UnparseableExtraConfigs)
}

// connectIdentity opens the connection the application resolves identity reads
// through, applying the same TFR_IDENTITY_SCHEMA_* rules cmd/server does.
//
// When the cutover is off, identity IS the registry connection; the returned
// closer is then a no-op so the deferred close in run() does not close a handle
// it already owns.
func connectIdentity(cfg *config.Config, registryDB *sql.DB) (*sql.DB, func(), error) {
	if os.Getenv("TFR_IDENTITY_SCHEMA_ENABLED") != "true" {
		return registryDB, func() {}, nil
	}
	name := os.Getenv("TFR_IDENTITY_SCHEMA_NAME")
	if name == "" {
		name = "identity"
	}
	idb, err := db.Connect(
		cfg.IdentityDatabase.GetDSNWithSearchPath(name+",public"),
		cfg.IdentityDatabase.MaxConnections, cfg.IdentityDatabase.MinIdleConnections,
	)
	if err != nil {
		return nil, nil, err
	}
	return idb, func() { _ = idb.Close() }, nil
}
