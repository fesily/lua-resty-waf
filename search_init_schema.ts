import fs from 'fs/promises'
import { WAF } from './Waf'
import linq from 'linq'
import { promisify } from 'util'
import { assert } from 'console'
import path from 'path'

function calcHitCount(l: Array<WAF.Rule>) {
  let count = 0
  for (const r of l) {
    count += r.vars.length
  }
  return count
}

function calcHitCountMap(l: Map<string, Map<string, WAF.Rule[]>>) {
  let count = 0
  for (const [_, rs] of l) {
    count += rs.size
  }
  return count
}

function mergeByVars(
  splitRules: Map<string, WAF.Rule[]>,
  originRules: WAF.Rule[]
) {
  const varsInfo = new Map<string, WAF.Rule.Var>()
  const newSplitRules = new Map<string, Map<string, WAF.Rule[]>>()
  for (const [k, sameTransformRules] of splitRules) {
    let mergedVarsRules = new Map<string, WAF.Rule[]>()
    for (const rule of sameTransformRules) {
      for (const _var of rule.vars) {
        let t = JSON.stringify(_var)
        if (varsInfo.has(t)) {
          console.assert(JSON.stringify(_var) === JSON.stringify(varsInfo.get(t)))
        }
        varsInfo.set(t, _var)
        if (mergedVarsRules.has(t)) mergedVarsRules.get(t)?.push(rule)
        else mergedVarsRules.set(t, [rule])
      }
    }
    mergedVarsRules = new Map(
      linq.from(mergedVarsRules.entries()).where((x) => x[1].length > 1)
    )

    newSplitRules.set(k, mergedVarsRules)
  }

  const result = new Map(linq
    .from(newSplitRules.entries())
    .where(x => x[1].size > 0).toArray())
  for (const [transform, rules] of result) {
    for (const [varK, rulesArr] of rules) {
      const var1 = varsInfo.get(varK) as WAF.Rule.Var
      for (let rule of rulesArr) {
        rule = linq.from(originRules).first((x) => x.id === rule.id)
        rule.vars = linq
          .from(rule.vars)
          .skipWhile((x) => x.type === var1.type)
          .toArray()
        // console.log(`remove vars rule id:${rule.id},var type:${k}`)
        if (rule.vars.length === 0) {
          // console.log(`remove empty vars rule id:${rule.id}`)
          originRules = linq
            .from(originRules)
            .skipWhile((x) => x.id === rule.id)
            .toArray()
        }
      }
    }
  }

  return { result, origin_rules: originRules }
}

function mergeByTransform(rules: Array<WAF.Rule>): Map<string, WAF.Rule[]> {
  const result = new Map<string, WAF.Rule[]>()
  for (const rule of rules) {
    let h = JSON.stringify(rule.opts?.transform || [])
    if (!result.has(h)) {
      result.set(h, [rule])
    } else result.get(h)?.push(rule)
  }
  return result
}
function isNumberString(x: string | number | bigint | boolean) {
  try {
    BigInt(x)
    return true
  } catch {
    return false
  }
}

function transformLabel(rule: WAF.Rule) {
  return rule.id
}

let nondisrupt_re = new RegExp('%\{([\._\dA-Za-z]+\)}')

function transformSetVar(v: WAF.Rule.Nondisrupt) {
  assert(v.data.col.match("[_\dA-Za-z]+"))
  assert(v.data.key.match("[_\dA-Za-z]+"))
  let value = v.data.value
  if (!isNumberString(value)) {
    let all_name: string[] = []
    value = value.replace(nondisrupt_re, x => { all_name.push(`collections.${x}`); return '%s' })
    if (value !== v.data.value)
      value = `string.format(${value},${all_name.join(',')})`
  }
  let operator = v.data.inc ? '+=' : '='
  return `ctx.storage.${v.data.col}.${v.data.key}${operator}${value}`
}

function transformSetRule(rule: WAF.Rule) {

}

function transformVar(s: string) {
  return s.replace(nondisrupt_re, x => `collections.${x}`)
}

function transformInit(rules: WAF.Rule[]) {
  //丢弃版本号检测
  rules = rules.filter((x, _1, _2) => x.id !== '901001')
  //读取所有初始化的规则SetRule
  let luaBlocks = linq.from(rules).where(x => x.actions.disrupt === 'IGNORE' && !!x.opts?.nolog && !!x.opts?.parsepattern && x.pattern === '0' && x.operator === 'EQUALS').where(x => {
    if (x.actions.nondisrupt?.length === 1 && x.vars.length === 1) {
      let nondisrupt = x.actions.nondisrupt[0]
      let vars = x.vars[0]
      if (nondisrupt.action === 'setvar' && vars.length === 1 && vars.storage === 1 && vars.parse?.length === 2) {
      }
      let parse = vars.parse
      if (parse[0] === 'specific' && nondisrupt.data.key === parse[1] && vars.type === nondisrupt.data.col) {
        return true
      }
    }
    return false
  })
  rules = linq.from(rules).except(luaBlocks).toArray()

  let s = luaBlocks.select(x => {
    const data = x.actions.nondisrupt[0].data
    console.assert(!!!data.inc)
    console.assert(!!x.vars[0].type)
    let defaultValue = data.value
    if (typeof (defaultValue) !== 'number') {
      console.assert(x.vars[0].type === 'TX')
      defaultValue = defaultValue.replace(nondisrupt_re, (_, p1) => p1)
      if (defaultValue === data.value)
        defaultValue = `[[${defaultValue}]]`
    }
    console.assert(data.col === 'TX')
    let value = `${data.col}.${data.key}`
    return `${value}= ${value} or ${defaultValue};`
  }).aggregate('ctx.storage.TX = ctx.storage.TX or {};local TX = ctx.storage.TX;TX.CRS_SETUP_VERSION=TX.CRS_SETUP_VERSION or 340;', (l, r) => l + r)
  //读取SetAction初始化
  luaBlocks = linq.from(rules).where(x => {
    if (x.opts?.nolog && x.vars.length === 1 && x.vars[0].unconditional === 1 && x.actions.disrupt === 'IGNORE') {
      return linq.from(x.actions.nondisrupt).all(v => v.action === 'setvar')
    }
    return false
  })
  s += luaBlocks.select(x => {
    let s = ''
    for (const { action, data } of x.actions.nondisrupt) {
      s = `${s};${data.col}.${data.key}=${data.value};`
    }
    return s
  }).aggregate('', (l, r) => l + r)
  rules = linq.from(rules).except(luaBlocks).toArray()
  return { s, rules }
}

function transformRule(rule: WAF.Rule) {
  if (rule.vars.length === 1 && rule.vars[0].unconditional === 1) {
    transformLabel(rule)
  } else if (rule.actions.disrupt === WAF.Rule.DisruptAction.IGNORE &&
    WAF.Rule.isTestOperator(rule.operator) &&
    rule.opts.parsepattern) {
    transformSetRule(rule)
  }
}

async function readAllRules(dirPath: string) {
  let files = await fs.readdir(dirPath)
  let rules = []
  for (const file of files) {
    rules.push(JSON.parse(await fs.readFile(path.join(dirPath, file), 'utf8')).access as WAF.Rule[])
  }
  return linq.from(rules).selectMany(x => x).toArray()
}
function isDETECTION_PARANOIA_LEVEL_Label(rule: WAF.Rule): boolean {
  if (rule.actions.disrupt === WAF.Rule.DisruptAction.IGNORE && !!rule.skip_after && rule.vars.length === 1 && rule.vars[0].type === "TX" && rule.vars[0].parse[1] === "DETECTION_PARANOIA_LEVEL") {
    isDETECTION_PARANOIA_LEVEL_Label.skip_afters.push(rule.skip_after)
    return true
  }
  return isDETECTION_PARANOIA_LEVEL_Label.skip_afters.findIndex(x => rule.id === x) !== -1
}
isDETECTION_PARANOIA_LEVEL_Label.skip_afters = new Array<string>();
function transform(allRules: WAF.Rule[]) {
  console.log(`rules len:${allRules.length},hit:${calcHitCount(allRules)}`)
  const pmRules: Array<WAF.Rule> = []
  const refindRules: Array<WAF.Rule> = []

  let arr = linq.from(allRules).groupBy(x => x.operator).toDictionary(x => x.key(), x => x.toArray())
  allRules = linq.from(allRules)
    .where((rule) => {
      if (rule.operator === 'PM') {
        console.assert(!!!rule.opts?.parsepattern)
        console.assert(linq.from(rule.vars).all(v => !!!v.unconditional))
        console.assert(!!!rule.op_negated)
        pmRules.push(rule)
        return false
      }
      return true
    })
    .toArray()
  allRules = linq.from(allRules).where(rule => {
    if (rule.operator === 'REFIND' && rule.opts?.parsepattern === undefined) {
      console.assert(linq.from(rule.vars).all(v => !!!v.unconditional))
      if (!!rule.op_negated) {
        rule = JSON.parse(JSON.stringify(rule))
        rule.pattern = `^(?:${rule.pattern})`
        rule.op_negated = undefined
      }
      refindRules.push(rule)
      return false
    }
    return true
  }).toArray()

  {
    const { result: refindRulesSplit, origin_rules: refindRules1 } = mergeByVars(mergeByTransform(refindRules), refindRules)
    const { result: PmRulesSplit, origin_rules: PmRules1 } = mergeByVars(mergeByTransform(pmRules), pmRules)
    console.log(`rules len:${allRules.length},merge pm rules hit:${calcHitCountMap(PmRulesSplit) + calcHitCount(PmRules1) + calcHitCountMap(refindRulesSplit) + calcHitCount(refindRules1) + calcHitCount(allRules)}`)
  }


}

function getParanoiaLevel(rule: WAF.Rule) {
  if (!!rule.tag) {
    let level = linq.from(rule.tag).firstOrDefault(x => x.startsWith("paranoia-level/"))
    return level ? level[level.length - 1] : -1
  }
  return -1;
}

async function main() {
  let allRules = await readAllRules("./rules/attack")
  {
    let initRules = await readAllRules("./rules/start")
    let { s, rules } = transformInit(initRules);
    await fs.writeFile('./rules/initlize.json', JSON.stringify(rules))
    s = `return function (ctx) ${s} end`
    await fs.writeFile('./rules/initlize.lua', s)
  }
  {
    //忽略finallize翻译

  }
  allRules = linq.from(allRules)
    .where(x => !isDETECTION_PARANOIA_LEVEL_Label(x))// 删除所有判断等级的规则
    .toArray()

  const subChain = linq.from(allRules).where(x => isNumberString(x.id)).groupBy(x => x.id).where(x => x.count() > 1).toDictionary(x => x.key(), x => x.skip(1).toArray())
  allRules = linq.from(allRules).except(subChain.toEnumerable().selectMany(x => x.value)).toArray()
  let paranoiaRules = linq.from(allRules).groupBy(getParanoiaLevel).toDictionary(x => x.key(), x => x.toArray());

  let levelRules = linq.range(1, 4).select(i => linq.range(1, i).select(j => paranoiaRules.get(j.toString())).selectMany(x => x).toArray()).toArray()
  for (const rules of levelRules) {
    transform(JSON.parse(JSON.stringify(rules)))
  }
}

promisify(main)()
