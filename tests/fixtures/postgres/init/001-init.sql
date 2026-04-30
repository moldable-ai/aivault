CREATE TABLE IF NOT EXISTS public.widgets (
  id integer PRIMARY KEY,
  name text NOT NULL,
  active boolean NOT NULL DEFAULT true
);

INSERT INTO public.widgets (id, name, active)
VALUES
  (1, 'alpha', true),
  (2, 'beta', false)
ON CONFLICT (id) DO UPDATE
SET name = EXCLUDED.name,
    active = EXCLUDED.active;
