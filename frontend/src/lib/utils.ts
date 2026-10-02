import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { t } from '@/lib/i18n'
export function cn(...inputs: ClassValue[]) { return twMerge(clsx(inputs)) }
export function message(error: unknown) { return error instanceof Error ? error.message : t('Request failed. Please try again.') }
