import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
export function cn(...inputs: ClassValue[]) { return twMerge(clsx(inputs)) }
export function message(error: unknown) { return error instanceof Error ? error.message : 'Request failed. Please try again.' }
