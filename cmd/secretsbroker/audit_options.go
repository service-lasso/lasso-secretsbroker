package main

import "flag"

type auditCommandOptions struct {
	Path      string
	HashChain bool
}

func addAuditCommandOptions(fs *flag.FlagSet) *auditCommandOptions {
	opts := &auditCommandOptions{}
	bindAuditCommandOptions(fs, &opts.Path, &opts.HashChain)
	return opts
}

func bindAuditCommandOptions(fs *flag.FlagSet, path *string, hashChain *bool) {
	fs.StringVar(path, "audit", getenvDefault("SECRETSBROKER_AUDIT_PATH", defaultAuditPath()), "audit JSONL path")
	fs.BoolVar(hashChain, "audit-hash-chain", envBoolDefault("SECRETSBROKER_AUDIT_HASH_CHAIN", false), "append tamper-evident audit hash-chain metadata")
}

func (opts *auditCommandOptions) newBackend(storePath, masterKey string) *localBackend {
	return newLocalBackendWithAudit(storePath, opts.Path, masterKey, opts.HashChain)
}

func newLocalBackendWithAudit(storePath, auditPath, masterKey string, hashChain bool) *localBackend {
	backend := newLocalBackend(storePath, auditPath, masterKey)
	backend.auditHashChain = hashChain
	return backend
}
