-- Revert module_versions.scm_repo_id FK back to no action on delete.
ALTER TABLE module_versions
    DROP CONSTRAINT module_versions_scm_repo_id_fkey,
    ADD CONSTRAINT module_versions_scm_repo_id_fkey
        FOREIGN KEY (scm_repo_id) REFERENCES module_scm_repos(id);
