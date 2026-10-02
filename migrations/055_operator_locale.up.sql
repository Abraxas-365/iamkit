-- 055: The console language an operator chose (L5). NULL: the browser's
-- language. Codes are the console catalogs' (management.ConsoleLocales).
ALTER TABLE operators ADD COLUMN locale text;
