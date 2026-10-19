import { readdir, readFile } from 'node:fs/promises'
import { join, relative } from 'node:path'

const META_TAG_RE = /<meta\b[^>]*>/gi

function decodeAttribute(value: string): string {
  return value
    .replaceAll('&quot;', '"')
    .replaceAll('&#39;', '\'')
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&')
}

function descriptionContents(html: string): string[] {
  const contents: string[] = []
  for (const match of html.matchAll(META_TAG_RE)) {
    const tag = match[0]
    if (!/\bname="description"/.test(tag)) {
      continue
    }
    const contentMatch = /\bcontent="([^"]*)"/.exec(tag)
    if (!contentMatch) {
      continue
    }
    contents.push(decodeAttribute(contentMatch[1]))
  }
  return contents
}

function isGarbled(content: string): boolean {
  return content.includes('navigation=') || content.startsWith('-')
}

async function htmlFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true })
  const files: string[] = []
  for (const entry of entries) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...await htmlFiles(path))
    } else if (entry.isFile() && entry.name.endsWith('.html')) {
      files.push(path)
    }
  }
  return files
}

/**
 * Fail the static docs build when a page summary was parsed as navigation
 * metadata (`navigation=`) or as a list (a summary that starts with `-`).
 */
export async function assertMetaDescriptions(publicDir: string): Promise<void> {
  const failures: string[] = []
  for (const file of await htmlFiles(publicDir)) {
    const html = await readFile(file, 'utf8')
    for (const content of descriptionContents(html)) {
      if (isGarbled(content)) {
        failures.push(`${relative(publicDir, file)}: ${content}`)
      }
    }
  }
  if (failures.length > 0) {
    throw new Error(`Garbled meta description (${failures.length}):\n${failures.join('\n')}`)
  }
}
