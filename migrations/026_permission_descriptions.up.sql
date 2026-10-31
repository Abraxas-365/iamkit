-- D40: permission descriptions. resources.permissions (text[]) stays the
-- source of truth for a resource's permission names; this table adds, per
-- permission, a display name and a sentence people read on the consent page,
-- in connected apps and in the console, with optional translations.
-- locale '' is the default text, shown when none matches the reader's
-- language; the permission's name is the last fallback. Rows only exist for
-- permissions of the catalog: removing a permission deletes its rows in the
-- same transaction (authzpg.UpdateCatalog), and replacing the set checks it
-- against the catalog under a lock on the resource row.
CREATE TABLE permission_descriptions (
    environment_id uuid NOT NULL,
    resource_id uuid NOT NULL,
    permission text NOT NULL,
    locale text DEFAULT ''::text NOT NULL,
    display_name text DEFAULT ''::text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT permission_descriptions_pkey PRIMARY KEY (resource_id, permission, locale),
    CONSTRAINT permission_descriptions_display_name_check CHECK ((char_length(display_name) <= 80)),
    CONSTRAINT permission_descriptions_description_check CHECK ((char_length(description) <= 300)),
    CONSTRAINT permission_descriptions_locale_check CHECK ((char_length(locale) <= 16)),
    CONSTRAINT permission_descriptions_text_check CHECK (((display_name <> ''::text) OR (description <> ''::text))),
    CONSTRAINT permission_descriptions_resource_fkey FOREIGN KEY (resource_id, environment_id) REFERENCES resources(id, environment_id) ON DELETE CASCADE
);
