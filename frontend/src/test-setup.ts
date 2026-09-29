import { configure } from '@testing-library/react'

// Page tests render the whole App; the first lazy route import can take
// longer than the 1s default when every test file runs in parallel.
configure({ asyncUtilTimeout: 5000 })
