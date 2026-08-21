import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { toast } from "sonner"
import { Sun, Moon, Plug, ShieldCheck, Info, LogOut, Sparkles, Save, FlaskConical, Trash2, Loader2, KeyRound } from "lucide-react"
import { api, getBase, clearAuth } from "@/lib/api"
import type { AiProvider, AiSettings, AiTestResult } from "@/lib/types"
import { confirmDialog } from "@/components/confirm"
import { SectionCard } from "@/components/ui-bits"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

const ANTHROPIC_DEFAULT_MODEL = "claude-opus-5"
const ANTHROPIC_DEFAULT_BASE = "https://api.anthropic.com"
const OPENAI_DEFAULT_BASE = "https://api.openai.com/v1"

/**
 * Server-side AI text assistant (powers ✨ Improve in the composer). Admin-only;
 * the key is sealed in the server DB and never comes back — only a masked hint.
 * The form is keyed on the fetched settings so it re-seeds after save/remove
 * without a setState-in-effect.
 */
function AiAssistantCard() {
  const q = useQuery({ queryKey: ["ai-settings"], queryFn: api.getAiSettings, staleTime: 30_000 })
  const [rev, setRev] = useState(0)
  return (
    <SectionCard
      title="AI assistant"
      icon={Sparkles}
      action={
        q.data?.configured ? (
          <span data-st="ok" className="rounded-full px-2 py-0.5 text-[11px] font-medium mono">
            {q.data.provider} · {q.data.model}
          </span>
        ) : (
          <span className="text-[11px] text-muted-foreground">not configured</span>
        )
      }
    >
      {q.isLoading ? (
        <div className="px-4 py-3 text-xs text-muted-foreground">loading…</div>
      ) : q.isError ? (
        <div className="px-4 py-3 text-xs text-st-down">
          {q.error instanceof Error ? q.error.message : "failed to load"}
          {q.error instanceof Error && /HTTP 404/.test(q.error.message) && " — the server doesn't expose /v1/settings/ai yet (upgrade ruwa)"}
        </div>
      ) : (
        <AiForm
          key={rev}
          initial={q.data ?? null}
          onChanged={async () => {
            await q.refetch()
            setRev((r) => r + 1)
          }}
        />
      )}
    </SectionCard>
  )
}

function AiForm({ initial, onChanged }: { initial: AiSettings | null; onChanged: () => Promise<void> }) {
  const configured = !!initial?.configured
  const [provider, setProvider] = useState<AiProvider>(initial?.provider ?? "anthropic")
  const [apiKey, setApiKey] = useState("")
  const [model, setModel] = useState(initial?.model ?? (initial?.provider === "openai" ? "" : ANTHROPIC_DEFAULT_MODEL))
  const [baseUrl, setBaseUrl] = useState(initial?.base_url ?? "")
  const [systemPrompt, setSystemPrompt] = useState(initial?.system_prompt ?? "")
  const [busy, setBusy] = useState<"save" | "test" | "remove" | null>(null)
  const [testRes, setTestRes] = useState<AiTestResult | null>(null)

  const providerChanged = configured && provider !== initial?.provider
  const needsKey = !configured || providerChanged
  // Default base URL shown as placeholder; blank = server default.
  const basePlaceholder = provider === "openai" ? OPENAI_DEFAULT_BASE : ANTHROPIC_DEFAULT_BASE

  function pickProvider(p: AiProvider) {
    setProvider(p)
    // Model defaults follow the provider; don't clobber a model the user typed
    // for the same provider that is already stored.
    if (p === "anthropic") setModel(initial?.provider === "anthropic" && initial.model ? initial.model : ANTHROPIC_DEFAULT_MODEL)
    else setModel(initial?.provider === "openai" && initial.model ? initial.model : "")
    setBaseUrl(initial?.provider === p ? initial.base_url ?? "" : "")
  }

  async function save() {
    if (needsKey && !apiKey.trim()) { toast.error("API key is required"); return }
    if (provider === "openai" && !model.trim()) { toast.error("Model is required for OpenAI-compatible providers"); return }
    setBusy("save")
    try {
      await api.putAiSettings({
        provider,
        ...(apiKey.trim() ? { api_key: apiKey.trim() } : {}),
        ...(model.trim() ? { model: model.trim() } : {}),
        base_url: baseUrl.trim() || null,
        system_prompt: systemPrompt.trim() || null,
      })
      toast.success("AI assistant saved")
      setApiKey("")
      setTestRes(null)
      await onChanged()
    } catch (e) {
      toast.error("Save failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(null)
    }
  }

  async function test() {
    setBusy("test")
    setTestRes(null)
    try {
      const r = await api.testAiSettings()
      setTestRes(r)
      toast.success(`${r.provider} · ${r.model} replied in ${r.latency_ms} ms`)
    } catch (e) {
      toast.error("Test failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(null)
    }
  }

  async function remove() {
    if (!(await confirmDialog({ title: "Remove AI assistant?", message: "Deletes the stored API key and settings from the server.", confirmLabel: "Remove", danger: true }))) return
    setBusy("remove")
    try {
      await api.deleteAiSettings()
      toast.success("AI assistant removed")
      await onChanged()
    } catch (e) {
      toast.error("Remove failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="space-y-3 px-4 py-3">
      <div className="text-xs text-muted-foreground">
        Powers <b className="text-foreground">✨ Improve</b> in the Messaging composer (rewrite, translate, fix grammar…).
        Stored server-side for all instances; the key is sealed and never returned to the browser.
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label className="mb-1.5 block">Provider</Label>
          <Select value={provider} onValueChange={(v) => pickProvider(v as AiProvider)}>
            <SelectTrigger size="sm" className="w-full text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="anthropic" className="text-xs">Anthropic</SelectItem>
              <SelectItem value="openai" className="text-xs">OpenAI-compatible</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="mb-1.5 block">Model{provider === "openai" && <span className="text-muted-foreground"> · required</span>}</Label>
          <Input
            className="mono text-xs"
            value={model}
            onChange={(e) => setModel(e.target.value)}
            placeholder={provider === "openai" ? "e.g. gpt-4.1-mini, llama-3.3-70b…" : ANTHROPIC_DEFAULT_MODEL}
          />
        </div>
      </div>
      <div>
        <Label className="mb-1.5 flex items-center gap-1.5"><KeyRound className="h-3.5 w-3.5" /> API key</Label>
        <Input
          type="password"
          autoComplete="off"
          className="mono text-xs"
          value={apiKey}
          onChange={(e) => setApiKey(e.target.value)}
          placeholder={
            configured && !providerChanged && initial?.api_key_hint
              ? `${initial.api_key_hint} (stored — leave blank to keep)`
              : provider === "anthropic" ? "sk-ant-…" : "sk-…"
          }
        />
      </div>
      {provider === "openai" && (
        <div>
          <Label className="mb-1.5 block">Base URL <span className="text-muted-foreground">· optional</span></Label>
          <Input className="mono text-xs" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder={basePlaceholder} />
          <div className="mt-1 text-[11px] text-muted-foreground">
            Any OpenAI-compatible <span className="mono">/chat/completions</span> endpoint works: OpenRouter, Groq, Ollama (<span className="mono">http://host:11434/v1</span>)…
          </div>
        </div>
      )}
      <div>
        <Label className="mb-1.5 block">System prompt <span className="text-muted-foreground">· optional, replaces the default</span></Label>
        <Textarea
          className="min-h-[64px] text-xs"
          value={systemPrompt}
          onChange={(e) => setSystemPrompt(e.target.value)}
          placeholder="You are a writing assistant for WhatsApp messages… (leave blank for the built-in prompt)"
        />
      </div>
      {testRes && (
        <div className="rounded-md bg-secondary px-3 py-2 text-[12px]">
          <span className="mono text-muted-foreground">{testRes.provider} · {testRes.model} · {testRes.latency_ms} ms</span>
          <div className="mt-0.5 whitespace-pre-wrap">{testRes.reply || "(empty reply)"}</div>
        </div>
      )}
      <div className="flex items-center justify-between gap-2 pt-1">
        <div className="flex items-center gap-2">
          <Button size="sm" onClick={save} disabled={busy !== null}>
            {busy === "save" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Save className="h-3.5 w-3.5" />} Save
          </Button>
          <Button size="sm" variant="outline" onClick={test} disabled={busy !== null || !configured} title={configured ? "Send a tiny test prompt" : "Save first"}>
            {busy === "test" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="h-3.5 w-3.5" />} Test
          </Button>
        </div>
        {configured && (
          <Button size="sm" variant="ghost" className="text-destructive hover:text-destructive" onClick={remove} disabled={busy !== null}>
            {busy === "remove" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />} Remove
          </Button>
        )}
      </div>
    </div>
  )
}

function Row({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b py-3 last:border-b-0">
      <div>
        <div className="text-[13px] font-medium">{label}</div>
        {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
      </div>
      <div className="flex items-center gap-2">{children}</div>
    </div>
  )
}

export function SettingsPage({
  theme, onToggleTheme, onLogout,
}: {
  theme: string
  onToggleTheme: () => void
  onLogout: () => void
}) {
  const health = useQuery({ queryKey: ["health-v"], queryFn: api.health, staleTime: 30_000 })

  return (
    <div className="mx-auto max-w-[660px] space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
        <div className="mt-0.5 text-xs text-muted-foreground">Console preferences (stored locally in this browser)</div>
      </div>

      <SectionCard title="Connection" icon={Plug}>
        <div className="px-4">
          <Row label="Base URL" hint="blank = same origin">
            <Input className="mono w-[280px] text-xs" defaultValue={getBase()} readOnly />
          </Row>
          <Row label="Admin token" hint="superuser, all instances">
            <Button size="sm" variant="outline" onClick={onLogout}><LogOut className="h-3.5 w-3.5" /> Re-enter / clear</Button>
          </Row>
        </div>
      </SectionCard>

      <SectionCard title="Preferences" icon={Sun}>
        <div className="px-4">
          <Row label="Theme" hint="dark is the default">
            <Button size="sm" variant="outline" onClick={onToggleTheme}>
              {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
              {theme === "dark" ? "Light" : "Dark"}
            </Button>
          </Row>
          <Row label="SSE auto-reconnect" hint="resume the live stream on drop">
            <Switch defaultChecked />
          </Row>
        </div>
      </SectionCard>

      <SectionCard title="Server" icon={ShieldCheck}>
        <div className="px-4">
          <Row label="Version" hint="reported by GET /health">
            <span data-st="ok" className="rounded-full px-2 py-0.5 text-[11px] font-medium mono">v{health.data?.version ?? "…"}</span>
          </Row>
          <Row label="Server mode" hint="RUWA_READONLY gate">
            <span className="text-[13px] text-muted-foreground">read/write</span>
          </Row>
        </div>
      </SectionCard>

      <AiAssistantCard />

      <SectionCard title="About" icon={Info}>
        <div className="space-y-1 px-4 py-3 text-[13px] text-muted-foreground">
          <div><b className="text-foreground">RUWA</b> — Rust WhatsApp. An in-house WhatsApp API (whatsmeow port) + this ops console.</div>
          <div className="mono text-xs">github.com/oqva-digital · /v1 bearer API · SSE events · Prometheus /metrics</div>
        </div>
      </SectionCard>
    </div>
  )
}

export { clearAuth }
