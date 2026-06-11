package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/DvGils/notenv/internal/backend"
	"github.com/DvGils/notenv/internal/config"
	"github.com/DvGils/notenv/internal/contract"
	"github.com/DvGils/notenv/internal/secrets"
	"github.com/DvGils/notenv/internal/ui"
)

// guardNamespace holds the contract's namespace to the checkout's local pin.
//
// The committed contract picks the namespace, and the namespace picks which
// secrets are decrypted into a child process — so an untrusted clone could
// otherwise name another project's namespace and have `notenv run` hand that
// project's secrets to its scripts. The storage target is already machine-only;
// this closes the same hole one level down. The decision matrix lives in
// config.CheckNamespacePin; this is the I/O around it.
//
// A first use whose namespace is just the directory's name still gets one
// check: if that namespace already holds secrets in the vault, this checkout
// is *joining* it — usually a legitimate new clone of your own project, but
// also exactly what a malicious repository named after your project looks
// like — so the join is confirmed once rather than pinned silently. A virgin
// namespace (the new-project flow) pins without ceremony.
func guardNamespace(ctx context.Context, store backend.Backend, dir string, binding config.LocalBinding, resolved string) error {
	decision, err := config.CheckNamespacePin(binding, resolved, filepath.Base(dir))
	if err != nil {
		return fmt.Errorf("%s: %w", filepath.Join(dir, contract.FileName), err)
	}
	switch decision {
	case config.NamespaceOK:
		return nil
	case config.NamespaceConfirm:
		if err := confirmNamespace(fmt.Sprintf("%s requests namespace %q, not this directory's name — expose that namespace's secrets to commands run here?", contract.FileName, resolved),
			fmt.Sprintf("%s requests namespace %q (not this directory's name %q); pinning it for this checkout", contract.FileName, resolved, filepath.Base(dir)), resolved); err != nil {
			return err
		}
	case config.NamespacePin:
		joining, err := secrets.Exists(ctx, store, resolved)
		if err != nil {
			return fmt.Errorf("check namespace %q before first use: %w", resolved, err)
		}
		if joining {
			if err := confirmNamespace(fmt.Sprintf("this checkout hasn't used notenv before, but namespace %q already holds secrets — expose them to commands run here?", resolved),
				fmt.Sprintf("first use in this checkout joins existing namespace %q; pinning it", resolved), resolved); err != nil {
				return err
			}
		}
	}
	pinNamespace(dir, binding, resolved)
	return nil
}

// confirmNamespace asks the user to accept a namespace before its first use in
// this checkout, or warns loudly where no one can answer (CI).
func confirmNamespace(question, ciWarning, resolved string) error {
	if !ui.Interactive() {
		ui.Warnf("%s", ciWarning)
		return nil
	}
	ok, err := ui.Confirm(question, false)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("namespace %q declined; fix the namespace in %s or run notenv in the right project", resolved, contract.FileName)
	}
	return nil
}

// pinNamespace records the accepted namespace in the local binding,
// best-effort: a read-only checkout still works, it just stays unpinned.
func pinNamespace(dir string, binding config.LocalBinding, namespace string) {
	binding.Namespace = namespace
	if _, err := config.WriteLocalBinding(dir, binding); err != nil {
		ui.Warnf("could not pin namespace %q in %s: %v (the contract-change guard stays off for this checkout)", namespace, config.LocalBindingFile, err)
		return
	}
	if err := ensureGitignore(dir, config.LocalBindingFile); err != nil {
		ui.Warnf("could not update .gitignore (add %q yourself): %v", config.LocalBindingFile, err)
	}
}
