-- Fix module_versions.scm_repo_id FK to use ON DELETE SET NULL.
-- Previously had no action, causing a FK violation when attempting to
-- unlink (delete) a module_scm_repos row that is still referenced by
-- existing module versions. Published versions should be retained when
-- a module is unlinked from SCM; their scm_repo_id simply becomes NULL.
ALTER TABLE module_versions
    DROP CONSTRAINT module_versions_scm_repo_id_fkey,
    ADD CONSTRAINT module_versions_scm_repo_id_fkey
        FOREIGN KEY (scm_repo_id) REFERENCES module_scm_repos(id) ON DELETE SET NULL;
