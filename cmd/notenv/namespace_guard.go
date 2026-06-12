package main

import (
	"context"
	"errors"
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
// secrets are decrypted into a child process, so an untrusted clone could
// otherwise name another project's namespace and have `notenv run` hand that
// project's secrets to its scripts. The storage target is already machine-only;
// this closes the same hole one level down. The decision matrix lives in
// config.CheckNamespacePin; this is the I/O around it.
//
// A first use whose namespace is just the directory's name still gets one
// check: if that namespace already holds secrets in the vault, this checkout
// is *joining* it, usually a legitimate new clone of your own project, but
// also exactly what a malicious repository named after your project looks
// like, so the join is confirmed once rather than pinned silently. A virgin
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
		if err := confirmNamespace(fmt.Sprintf("%s requests namespace %q, not this directory's name. Expose that namespace's secrets to commands run here?", contract.FileName, resolved),
			fmt.Sprintf("%s requests namespace %q (not this directory's name %q); pinning it for this checkout", contract.FileName, resolved, filepath.Base(dir)),
			fmt.Sprintf("namespace %q declined; fix the namespace in %s or run notenv in the right project", resolved, contract.FileName)); err != nil {
			return err
		}
	case config.NamespacePin:
		joining, err := secrets.Exists(ctx, store, resolved)
		if err != nil {
			return fmt.Errorf("check namespace %q before first use: %w", resolved, err)
		}
		if joining {
			if err := confirmNamespace(fmt.Sprintf("this checkout hasn't used notenv before, but namespace %q already holds secrets. Expose them to commands run here?", resolved),
				fmt.Sprintf("first use in this checkout joins existing namespace %q; pinning it", resolved),
				fmt.Sprintf("namespace %q declined; fix the namespace in %s or run notenv in the right project", resolved, contract.FileName)); err != nil {
				return err
			}
		}
	}
	pinNamespace(dir, binding, resolved)
	return nil
}

// guardFlagNamespace holds an explicitly named namespace (--namespace) to the
// user-level acceptance record. Unlike a committed contract, the flag is
// chosen by the invoker, so it cannot be planted by a cloned repository, but
// it is exactly how a misdirected agent would be steered at another project's
// secrets, so joining a namespace that already holds secrets is confirmed once
// per (storage, namespace). Acceptance is recorded user-level: there is no
// checkout to pin in. A virgin namespace is the new-project flow and pins
// without ceremony, same as a checkout's.
func guardFlagNamespace(ctx context.Context, store backend.Backend, scope, namespace string) error {
	accepted, err := config.NamespaceAccepted(scope, namespace)
	if err != nil {
		return err
	}
	if accepted {
		return nil
	}
	joining, err := secrets.Exists(ctx, store, namespace)
	if err != nil {
		return fmt.Errorf("check namespace %q before first use: %w", namespace, err)
	}
	if joining {
		if err := confirmNamespace(fmt.Sprintf("namespace %q already holds secrets. Expose them to commands run here?", namespace),
			fmt.Sprintf("first explicit use of namespace %q on this storage joins its existing secrets; accepting it", namespace),
			fmt.Sprintf("namespace %q declined; check the --namespace value", namespace)); err != nil {
			return err
		}
	}
	if err := config.AcceptNamespace(scope, namespace); err != nil {
		ui.Warnf("could not record acceptance of namespace %q: %v (you may be asked again)", namespace, err)
	}
	return nil
}

// confirmNamespace asks the user to accept a namespace before its first use,
// or warns loudly where no one can answer (CI). decline is the error a refusal
// surfaces, pointing at where the namespace was chosen.
func confirmNamespace(question, ciWarning, decline string) error {
	if !ui.Interactive() {
		ui.Warnf("%s", ciWarning)
		return nil
	}
	ok, err := ui.Confirm(question, false)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New(decline)
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
