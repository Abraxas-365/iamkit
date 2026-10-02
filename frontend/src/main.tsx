import { loadLanguage } from '@/lib/i18n'

// The catalog loads before any page module is evaluated, so module-level
// tables built with t() (labels, column headers) are already translated.
// A failed catalog load leaves English.
void loadLanguage().catch(() => {}).finally(() => import('./boot'))
