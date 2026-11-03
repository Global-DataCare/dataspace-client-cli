// Flow contract: the public onboarding CLI exposes one locally resolvable rules graph without turning generated keys, scopes or submissions into deployment authority.
import assert from 'node:assert/strict'
import { access, readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import test from 'node:test'

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..')

function relativeTargets(markdown) {
  return [...markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/gu)]
    .map(([, target]) => target)
    .filter((target) => !/^(?:https?:|mailto:|#)/u.test(target))
}

test('keeps onboarding CLI rules linked and locally resolvable', async () => {
  const agentsPath = resolve(repositoryRoot, 'AGENTS.md')
  const indexPath = resolve(repositoryRoot, 'docs/RULES_INDEX.md')
  const agents = await readFile(agentsPath, 'utf8')
  const index = await readFile(indexPath, 'utf8')

  assert.match(agents, /docs\/RULES_INDEX\.md/u)
  assert.match(index, /README\.md/u)
  assert.match(index, /scope-contract\.test\.js/u)

  for (const [path, markdown] of [[agentsPath, agents], [indexPath, index]]) {
    for (const target of relativeTargets(markdown)) {
      await access(resolve(dirname(path), target.split('#', 1)[0]))
    }
  }
})
