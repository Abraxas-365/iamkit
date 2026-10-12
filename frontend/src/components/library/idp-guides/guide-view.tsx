import { useState } from 'react'
import { CopyField, DetailSection, selectClass } from '@/components/library/patterns'
import { t } from '@/lib/i18n'
import { guideLabel, scimGuides, type Guide, type GuideValue } from './guides'

export type GuideValues = Partial<Record<GuideValue, string>>

/** GuideView renders a guide's numbered steps; a step that needs IAMKit values
 * shows them with copy buttons, then the attributes and troubleshooting. */
export function GuideView({ guide, values, missing }: { guide: Guide; values: GuideValues; missing?: Partial<Record<GuideValue, string>> }) {
  return <div className="space-y-4">
    <ol className="space-y-3">
      {guide.steps.map((step, i) => <li key={step.title} className="space-y-2">
        <p className="text-sm font-medium">{i + 1}. {step.title}</p>
        <p className="text-sm text-muted-foreground">{step.body}</p>
        {step.values?.map(name => values[name]
          ? <CopyField key={name} label={guideLabel(name)} value={values[name] as string} secret={name === 'scim_token'} />
          : missing?.[name] ? <p key={name} className="text-xs text-muted-foreground">{guideLabel(name)}: {missing[name]}</p> : null)}
      </li>)}
    </ol>
    <details className="rounded-md border p-3 text-sm">
      <summary className="cursor-pointer font-medium">{t('Attributes to send')}</summary>
      <dl className="mt-2 space-y-1">
        {guide.attributes.map(([name, what]) => <div key={name} className="flex flex-wrap gap-x-2"><dt><code className="text-xs">{name}</code></dt><dd className="text-muted-foreground">{what}</dd></div>)}
      </dl>
    </details>
    <details className="rounded-md border p-3 text-sm">
      <summary className="cursor-pointer font-medium">{t('Troubleshooting')}</summary>
      <ul className="mt-2 space-y-2">
        {guide.troubleshooting.map(item => <li key={item.problem}><p className="font-medium">{item.problem}</p><p className="text-muted-foreground">{item.fix}</p></li>)}
      </ul>
    </details>
  </div>
}

/** ScimGuides is the directory page's setup help: pick Okta or Entra ID and
 * follow the steps with the SCIM URL (and, when one was just issued, token). */
export function ScimGuides({ url, token }: { url: string; token?: string }) {
  const [id, setId] = useState('')
  const guide = scimGuides.find(g => g.id === id)
  return <DetailSection title={t('Setup guides')} description={t('Step-by-step help for connecting your directory to IAMKit.')}>
    <div className="space-y-3">
      <select aria-label={t('Directory guide')} className={selectClass} value={id} onChange={e => setId(e.target.value)}>
        <option value="">{t('Choose your directory…')}</option>
        {scimGuides.map(g => <option key={g.id} value={g.id}>{g.label}</option>)}
      </select>
      {guide && <GuideView guide={guide} values={{ scim_url: url, ...(token ? { scim_token: token } : {}) }} missing={{ scim_token: t('shown once when you add a token; copy it then.') }} />}
    </div>
  </DetailSection>
}
