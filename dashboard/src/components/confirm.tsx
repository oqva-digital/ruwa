import { useEffect, useState } from "react"
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

interface Req {
  kind: "confirm" | "prompt"
  title: string
  message?: string
  confirmLabel?: string
  danger?: boolean
  defaultValue?: string
  placeholder?: string
  resolve: (v: boolean | string | null) => void
}

let push: ((r: Req) => void) | null = null

/** Promise-based in-app confirm (shadcn AlertDialog). Resolves true/false. */
export function confirmDialog(o: {
  title: string
  message?: string
  confirmLabel?: string
  danger?: boolean
}): Promise<boolean> {
  return new Promise((res) => {
    if (!push) return res(false)
    push({ kind: "confirm", ...o, resolve: (v) => res(!!v) })
  })
}

/** Promise-based in-app text prompt (shadcn Dialog). Resolves string or null. */
export function promptDialog(o: {
  title: string
  message?: string
  defaultValue?: string
  placeholder?: string
  confirmLabel?: string
}): Promise<string | null> {
  return new Promise((res) => {
    if (!push) return res(null)
    push({ kind: "prompt", ...o, resolve: (v) => res(typeof v === "string" ? v : null) })
  })
}

/** Mounted once at the app root; renders whatever dialog is pending. */
export function DialogHost() {
  const [req, setReq] = useState<Req | null>(null)
  const [val, setVal] = useState("")

  useEffect(() => {
    push = (r) => {
      setVal(r.defaultValue ?? "")
      setReq(r)
    }
    return () => {
      push = null
    }
  }, [])

  function done(result: boolean | string | null) {
    req?.resolve(result)
    setReq(null)
  }

  if (req?.kind === "confirm") {
    return (
      <AlertDialog open onOpenChange={(o) => !o && done(false)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{req.title}</AlertDialogTitle>
            {req.message && <AlertDialogDescription>{req.message}</AlertDialogDescription>}
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel onClick={() => done(false)}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className={req.danger ? "bg-destructive text-destructive-foreground hover:bg-destructive/90" : ""}
              onClick={() => done(true)}
            >
              {req.confirmLabel ?? "Confirm"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    )
  }

  if (req?.kind === "prompt") {
    return (
      <Dialog open onOpenChange={(o) => !o && done(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{req.title}</DialogTitle>
            {req.message && <DialogDescription>{req.message}</DialogDescription>}
          </DialogHeader>
          <Input
            autoFocus
            value={val}
            placeholder={req.placeholder}
            onChange={(e) => setVal(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && done(val)}
          />
          <DialogFooter>
            <Button variant="ghost" onClick={() => done(null)}>Cancel</Button>
            <Button onClick={() => done(val)}>{req.confirmLabel ?? "OK"}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )
  }

  return null
}
