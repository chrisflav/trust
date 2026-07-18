import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'
import { marksApi } from './marksApi'

const here = dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  // `marksApi` only attaches while serving, so the production build stays a
  // plain static site with no write path.
  plugins: [react(), marksApi(resolve(here, '..', 'trust-marks.json'))],
})