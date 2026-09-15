import { useEffect, useRef, useState } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Mic, MicOff, Phone, PhoneIncoming, PhoneOff, PhoneOutgoing, Video } from "lucide-react"
import { toast } from "sonner"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { api } from "@/lib/api"
import { isCallAudioSupported, startCallAudio, type CallAudioHandle } from "@/lib/call-audio"
import { isCloud, type CallInfo, type SessionMeta } from "@/lib/types"

/** "5511999999999@s.whatsapp.net" → "+5511999999999"; LIDs stay opaque. */
function peerLabel(from: string): string {
  const user = from.split("@")[0].split(":")[0]
  return from.endsWith("@lid") ? user : `+${user}`
}

function fmtDuration(sec: number): string {
  const m = Math.floor(sec / 60)
  const s = sec % 60
  return `${m}:${String(s).padStart(2, "0")}`
}

type ActiveCall = {
  /** call_id for an answered inbound call; null while an outbound dial rings
   * (the server assigns it, we don't need it client-side). */
  callId: string | null
  from: string
  outbound: boolean
  /** epoch ms when the bridge's `start` frame arrived (null while connecting). */
  startedAt: number | null
}

export function CallsPage({ inst, readonly = false }: { inst: SessionMeta; readonly?: boolean }) {
  const qc = useQueryClient()
  const [active, setActive] = useState<ActiveCall | null>(null)
  const [muted, setMuted] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [dialTo, setDialTo] = useState("")
  const audioRef = useRef<CallAudioHandle | null>(null)
  const cloud = isCloud(inst)
  const supported = isCallAudioSupported()

  const callsQ = useQuery({
    queryKey: ["calls", inst.id],
    queryFn: () => api.listCalls(inst.id),
    enabled: !cloud,
    refetchInterval: 2500,
  })
  const ringing = (callsQ.data ?? []).filter((c) => c.call_id !== active?.callId)

  // In-call duration ticker.
  useEffect(() => {
    if (!active?.startedAt) return
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - active.startedAt!) / 1000)), 500)
    return () => clearInterval(t)
  }, [active?.startedAt])

  // Leaving the page (or unmounting) hangs up — the socket IS the call.
  useEffect(() => () => audioRef.current?.stop(), [])

  const bridgeErr = (e: unknown, verb: string) => {
    setActive(null)
    const name = e instanceof DOMException ? e.name : ""
    if (name === "NotAllowedError")
      toast.error("Microphone access denied", { description: `Allow mic access in the browser to ${verb} calls.` })
    else toast.error(`Could not ${verb} the call`, { description: e instanceof Error ? e.message : String(e) })
  }

  const openBridge = async (wsUrl: string, seed: ActiveCall) => {
    setActive(seed)
    setMuted(false)
    setElapsed(0)
    audioRef.current = await startCallAudio(wsUrl, {
      onStart: (info) =>
        setActive((a) =>
          a ? { ...a, startedAt: Date.now(), from: (info.from as string) || a.from } : a,
        ),
      onClose: () => {
        audioRef.current = null
        setActive(null)
        qc.invalidateQueries({ queryKey: ["calls", inst.id] })
      },
    })
  }

  const answer = async (call: CallInfo) => {
    if (audioRef.current) return
    try {
      await openBridge(api.callAudioUrl(inst.id, call.call_id), {
        callId: call.call_id,
        from: call.from,
        outbound: false,
        startedAt: null,
      })
    } catch (e) {
      bridgeErr(e, "answer")
    }
  }

  const dial = async () => {
    const peer = dialTo.trim()
    if (!peer || audioRef.current) return
    try {
      await openBridge(api.dialAudioUrl(inst.id, peer), {
        callId: null,
        from: peer,
        outbound: true,
        startedAt: null,
      })
      setDialTo("")
    } catch (e) {
      bridgeErr(e, "place")
    }
  }

  const reject = async (call: CallInfo) => {
    try {
      await api.rejectCall(inst.id, call.call_id, call.from)
      toast.success("Call declined")
      qc.invalidateQueries({ queryKey: ["calls", inst.id] })
    } catch (e) {
      toast.error("Reject failed", { description: e instanceof Error ? e.message : String(e) })
    }
  }

  const hangup = () => audioRef.current?.stop()

  const toggleMute = () => {
    const next = !muted
    audioRef.current?.setMuted(next)
    setMuted(next)
  }

  if (cloud) {
    return (
      <div>
        <Header />
        <Card className="mx-auto max-w-[480px] p-6 text-sm text-muted-foreground">
          Voice calls need a linked WhatsApp Web device — they aren't available on Cloud API sessions.
        </Card>
      </div>
    )
  }

  return (
    <div>
      <Header />
      <div className="mx-auto flex max-w-[480px] flex-col gap-4">
        {!supported && (
          <Card className="p-4 text-xs text-muted-foreground">
            This browser can't capture call audio (needs getUserMedia + AudioWorklet over HTTPS).
          </Card>
        )}

        {!active && !readonly && (
          <Card className="flex items-center gap-2 p-4">
            <Input
              value={dialTo}
              onChange={(e) => setDialTo(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && dial()}
              placeholder="Phone number, e.g. 5511999999999"
              inputMode="tel"
              disabled={!supported}
            />
            <Button onClick={dial} disabled={!supported || !dialTo.trim()}>
              <PhoneOutgoing className="mr-1.5 h-3.5 w-3.5" /> Call
            </Button>
          </Card>
        )}

        {active && (
          <Card className="flex flex-col items-center gap-4 p-6">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10 text-primary">
              {active.outbound ? <PhoneOutgoing className="h-5 w-5" /> : <Phone className="h-5 w-5" />}
            </div>
            <div className="text-center">
              <div className="mono text-sm font-medium">{peerLabel(active.from)}</div>
              <div className="mt-1 text-xs text-muted-foreground tnum">
                {active.startedAt
                  ? fmtDuration(elapsed)
                  : active.outbound
                    ? "Ringing…"
                    : "Connecting…"}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button variant={muted ? "default" : "outline"} size="sm" onClick={toggleMute}>
                {muted ? <MicOff className="mr-1.5 h-3.5 w-3.5" /> : <Mic className="mr-1.5 h-3.5 w-3.5" />}
                {muted ? "Unmute" : "Mute"}
              </Button>
              <Button variant="destructive" size="sm" onClick={hangup}>
                <PhoneOff className="mr-1.5 h-3.5 w-3.5" /> Hang up
              </Button>
            </div>
          </Card>
        )}

        {ringing.map((c) => (
          <Card key={c.call_id} className="flex items-center justify-between gap-3 p-4">
            <div className="flex min-w-0 items-center gap-3">
              <div className="flex h-9 w-9 flex-none animate-pulse items-center justify-center rounded-full bg-emerald-500/10 text-emerald-500">
                {c.is_video ? <Video className="h-4 w-4" /> : <PhoneIncoming className="h-4 w-4" />}
              </div>
              <div className="min-w-0">
                <div className="mono truncate text-sm font-medium">{peerLabel(c.from)}</div>
                <div className="text-xs text-muted-foreground">
                  Incoming {c.is_video ? "video (audio-only answer)" : "voice"} call…
                </div>
              </div>
            </div>
            {!readonly && (
              <div className="flex flex-none items-center gap-2">
                <Button size="sm" variant="destructive" onClick={() => reject(c)}>
                  Decline
                </Button>
                <Button size="sm" disabled={!supported || !!active} onClick={() => answer(c)}>
                  <Phone className="mr-1.5 h-3.5 w-3.5" /> Answer
                </Button>
              </div>
            )}
          </Card>
        ))}

        {!active && ringing.length === 0 && (
          <Card className="flex flex-col items-center gap-2 p-8 text-center">
            <Phone className="h-5 w-5 text-muted-foreground" />
            <div className="text-sm font-medium">No calls right now</div>
            <div className="max-w-[320px] text-xs text-muted-foreground">
              Incoming voice calls ring here — answer and talk straight from the console, or decline.
            </div>
          </Card>
        )}
      </div>
    </div>
  )
}

function Header() {
  return (
    <div className="mb-4">
      <h1 className="text-xl font-semibold tracking-tight">Calls</h1>
      <div className="mt-0.5 text-xs text-muted-foreground">
        Place and answer WhatsApp voice calls right in the browser (mic + speaker).
      </div>
    </div>
  )
}
