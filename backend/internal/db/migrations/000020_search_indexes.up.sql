-- Add tsvector columns
ALTER TABLE modules ADD COLUMN search_vector tsvector;
ALTER TABLE providers ADD COLUMN search_vector tsvector;

-- Populate existing data with weighted vectors
UPDATE modules SET search_vector =
  setweight(to_tsvector('english', coalesce(name, '')), 'A') ||
  setweight(to_tsvector('english', coalesce(namespace, '')), 'B') ||
  setweight(to_tsvector('english', coalesce(description, '')), 'C') ||
  setweight(to_tsvector('english', coalesce(system, '')), 'B');

UPDATE providers SET search_vector =
  setweight(to_tsvector('english', coalesce(type, '')), 'A') ||
  setweight(to_tsvector('english', coalesce(namespace, '')), 'B') ||
  setweight(to_tsvector('english', coalesce(description, '')), 'C');

-- GIN indexes for fast search
CREATE INDEX idx_modules_search ON modules USING GIN(search_vector);
CREATE INDEX idx_providers_search ON providers USING GIN(search_vector);

-- Auto-update trigger for modules
CREATE OR REPLACE FUNCTION modules_search_vector_update() RETURNS trigger AS $$
BEGIN
  NEW.search_vector :=
    setweight(to_tsvector('english', coalesce(NEW.name, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(NEW.namespace, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(NEW.description, '')), 'C') ||
    setweight(to_tsvector('english', coalesce(NEW.system, '')), 'B');
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER trg_modules_search_vector
  BEFORE INSERT OR UPDATE OF name, namespace, description, system ON modules
  FOR EACH ROW EXECUTE FUNCTION modules_search_vector_update();

-- Auto-update trigger for providers
CREATE OR REPLACE FUNCTION providers_search_vector_update() RETURNS trigger AS $$
BEGIN
  NEW.search_vector :=
    setweight(to_tsvector('english', coalesce(NEW.type, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(NEW.namespace, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(NEW.description, '')), 'C');
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER trg_providers_search_vector
  BEFORE INSERT OR UPDATE OF type, namespace, description ON providers
  FOR EACH ROW EXECUTE FUNCTION providers_search_vector_update();
