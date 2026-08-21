// Cloud API (kind: "cloud") helpers shared by the create dialog, the overview
// credentials editor and the messaging composer.
import { getBase } from "./api"
import type { CloudCredsInput, TemplateRow } from "./types"

export const GRAPH_VERSION_DEFAULT = "v25.0"

/** Where Meta must POST inbound webhooks: the API origin (not necessarily the
 *  console's) + the fixed ruwa path. Same for every cloud session. */
export function cloudWebhookUrl(): string {
  return (getBase() || window.location.origin) + "/v1/cloud/webhook"
}

export interface CloudForm {
  phone_number_id: string
  waba_id: string
  access_token: string
  app_secret: string
  verify_token: string
  graph_version: string
}
export const EMPTY_CLOUD: CloudForm = {
  phone_number_id: "", waba_id: "", access_token: "", app_secret: "", verify_token: "", graph_version: GRAPH_VERSION_DEFAULT,
}

export type CloudFormErrors = Partial<Record<keyof CloudForm, string>>

/** Client-side mirror of the server's validation for cloud creds. `forCreate`
 *  makes phone_number_id / access_token mandatory (waba_id is optional — only
 *  template management needs it, matching the API and MCP); on update blank
 *  fields mean "keep current". */
export function validateCloudForm(c: CloudForm, forCreate: boolean): CloudFormErrors {
  const errs: CloudFormErrors = {}
  const idOk = (v: string) => /^\d{5,}$/.test(v)
  if (forCreate || c.phone_number_id) {
    if (!c.phone_number_id) errs.phone_number_id = "Required"
    else if (!idOk(c.phone_number_id)) errs.phone_number_id = "Numeric Meta id (digits only)"
  }
  if (c.waba_id && !idOk(c.waba_id)) errs.waba_id = "Numeric Meta id (digits only)"
  if (forCreate && !c.access_token) errs.access_token = "Required"
  if (c.access_token && /\s/.test(c.access_token)) errs.access_token = "Token must not contain whitespace"
  if (c.graph_version && !/^v\d+\.\d+$/.test(c.graph_version)) errs.graph_version = "Format: v25.0"
  return errs
}

/** Trim + drop blank fields → the wire `cloud` object. On create the default
 *  graph_version is filled in; on update blanks are omitted (keep current). */
export function cloudFormToInput(c: CloudForm, forCreate: boolean): CloudCredsInput {
  const out: CloudCredsInput = {}
  const put = (k: keyof CloudForm) => { const v = c[k].trim(); if (v) out[k] = v }
  ;(["phone_number_id", "waba_id", "access_token", "app_secret", "verify_token", "graph_version"] as const).forEach(put)
  if (forCreate && !out.graph_version) out.graph_version = GRAPH_VERSION_DEFAULT
  return out
}

/** Text of a template's BODY component, if any. */
export function templateBodyText(t: TemplateRow): string | null {
  const body = t.components?.find((c) => c.type?.toUpperCase() === "BODY")
  return typeof body?.text === "string" ? body.text : null
}

/** How many positional `{{n}}` parameters a template body expects (max index). */
export function countBodyParams(text: string | null | undefined): number {
  if (!text) return 0
  let max = 0
  for (const m of text.matchAll(/\{\{\s*(\d+)\s*\}\}/g)) max = Math.max(max, Number(m[1]))
  return max
}

/** Substitute `{{n}}` with the given params (or a visible placeholder) for a preview. */
export function fillTemplateBody(text: string, params: string[]): string {
  return text.replace(/\{\{\s*(\d+)\s*\}\}/g, (_, n: string) => {
    const v = params[Number(n) - 1]
    return v && v.length ? v : `{{${n}}}`
  })
}
