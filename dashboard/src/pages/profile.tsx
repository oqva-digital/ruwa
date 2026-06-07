import { useState } from "react"
import { toast } from "sonner"
import { Save, Upload, UserCircle } from "lucide-react"
import { api } from "@/lib/api"
import type { SessionMeta } from "@/lib/types"
import { SectionCard } from "@/components/ui-bits"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"

export function ProfilePage({ inst, readonly }: { inst: SessionMeta; readonly: boolean }) {
  const [name, setName] = useState(inst.label ?? "")
  const [status, setStatus] = useState("")
  const [picture, setPicture] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]
    if (!f) return
    const reader = new FileReader()
    reader.onload = () => {
      const dataUrl = String(reader.result)
      setPicture(dataUrl.split(",")[1] ?? null) // raw base64
    }
    reader.readAsDataURL(f)
  }

  async function save() {
    setBusy(true)
    try {
      const body: { name?: string; status?: string; picture?: string } = {}
      if (name.trim()) body.name = name.trim()
      if (status.trim()) body.status = status.trim()
      if (picture) body.picture = picture
      const res = await api.setProfile(inst.id, body)
      toast.success("Profile updated", { description: `Applied: ${res.applied?.join(", ") || "—"}` })
    } catch (e) {
      toast.error("Save failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-[560px]">
      <div className="mb-4">
        <h1 className="text-xl font-semibold tracking-tight">My Profile</h1>
        <div className="mt-0.5 text-xs text-muted-foreground">The connected account for {inst.label ?? inst.id}</div>
      </div>

      <SectionCard title="Account profile" icon={UserCircle}>
        <div className="space-y-4 p-4">
          <div className="flex items-center gap-4">
            <div className="grid h-16 w-16 place-items-center overflow-hidden rounded-full bg-secondary text-muted-foreground">
              {picture ? <img src={`data:image/jpeg;base64,${picture}`} className="h-full w-full object-cover" alt="" /> : <UserCircle className="h-8 w-8" />}
            </div>
            <label className="cursor-pointer">
              <input type="file" accept="image/jpeg,image/png" className="hidden" onChange={onFile} disabled={readonly} />
              <span className="inline-flex h-9 items-center gap-1.5 rounded-md border px-3 text-[13px] font-medium hover:bg-accent">
                <Upload className="h-3.5 w-3.5" /> Upload JPEG
              </span>
            </label>
          </div>
          <div>
            <Label className="mb-1.5 block">Display name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="My Business" />
          </div>
          <div>
            <Label className="mb-1.5 block">Status / about</Label>
            <Textarea value={status} onChange={(e) => setStatus(e.target.value)} placeholder="Available on WhatsApp" className="h-20" />
          </div>
          <div className="flex justify-end border-t pt-3">
            <Button disabled={readonly || busy} onClick={save}><Save className="h-4 w-4" /> Save</Button>
          </div>
        </div>
      </SectionCard>
    </div>
  )
}
