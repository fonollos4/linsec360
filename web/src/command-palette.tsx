import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { ArrowUpRight, FileCode2, HardDrive, Play, Search, X } from 'lucide-react'
import { api } from './api'
import { navGroups } from './nav-items'

type Command = {
  id: string
  label: string
  detail: string
  group: string
  to: string
  icon: typeof Search
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement | null>(null)
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)

  const hosts = useQuery({ queryKey: ['hosts'], queryFn: () => api.hosts({ limit: 500 }), enabled: open })
  const playbooks = useQuery({ queryKey: ['playbooks'], queryFn: api.playbooks, enabled: open })
  const deployments = useQuery({ queryKey: ['deployments', 'palette'], queryFn: () => api.deployments({ limit: 20 }), enabled: open })

  const commands = useMemo<Command[]>(() => {
    const items: Command[] = []
    for (const group of navGroups) {
      for (const item of group.items) {
        items.push({ id: `nav-${item.to}`, label: item.label, detail: group.label, group: 'Pages', to: item.to, icon: item.icon })
      }
    }
    for (const host of hosts.data ?? []) {
      items.push({ id: `host-${host.id}`, label: host.name, detail: `${host.ip} · ${host.environment}`, group: 'Hôtes', to: `/hosts/${host.id}`, icon: HardDrive })
    }
    for (const playbook of playbooks.data ?? []) {
      items.push({ id: `playbook-${playbook.filename}`, label: playbook.filename, detail: playbook.description || 'Playbook Ansible', group: 'Playbooks', to: '/playbooks', icon: FileCode2 })
    }
    for (const deployment of deployments.data?.items ?? []) {
      items.push({ id: `deployment-${deployment.id}`, label: `Déploiement ${deployment.id}`, detail: `${deployment.playbook} · ${deployment.environment}`, group: 'Déploiements', to: `/deployments/${deployment.id}`, icon: Play })
    }
    return items
  }, [hosts.data, playbooks.data, deployments.data])

  const results = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const filtered = needle
      ? commands.filter((command) => `${command.label} ${command.detail}`.toLowerCase().includes(needle))
      : commands.filter((command) => command.group === 'Pages' || command.group === 'Hôtes')
    return filtered.slice(0, 40)
  }, [commands, query])

  useEffect(() => {
    if (!open) return
    const timer = window.setTimeout(() => inputRef.current?.focus(), 20)
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKey)
    return () => {
      window.clearTimeout(timer)
      document.removeEventListener('keydown', handleKey)
    }
  }, [open, onClose])

  const selectedIndex = Math.min(active, Math.max(0, results.length - 1))

  if (!open) return null

  const select = (command: Command) => {
    onClose()
    navigate(command.to)
  }

  return createPortal(
    <div className="command-backdrop" role="presentation" onClick={onClose}>
      <div className="command-palette" role="dialog" aria-modal="true" aria-label="Recherche globale" onClick={(event) => event.stopPropagation()}>
        <div className="command-input">
          <Search />
          <input
            ref={inputRef}
            value={query}
            placeholder="Rechercher un hôte, un playbook, un déploiement…"
            aria-label="Recherche globale"
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'ArrowDown') {
                event.preventDefault()
                setActive((current) => Math.min(current + 1, results.length - 1))
              } else if (event.key === 'ArrowUp') {
                event.preventDefault()
                setActive((current) => Math.max(current - 1, 0))
              } else if (event.key === 'Enter' && results[selectedIndex]) {
                event.preventDefault()
                select(results[selectedIndex])
              }
            }}
          />
          <button className="icon-button" aria-label="Fermer la recherche" onClick={onClose}><X /></button>
        </div>
        <div className="command-results">
          {!results.length && <div className="command-empty">Aucun résultat pour « {query} »</div>}
          {results.map((command, index) => {
            const Icon = command.icon
            return (
              <button
                key={command.id}
                className={`command-result${index === selectedIndex ? ' active' : ''}`}
                onMouseEnter={() => setActive(index)}
                onClick={() => select(command)}
              >
                <Icon />
                <span><strong>{command.label}</strong><small>{command.detail}</small></span>
                <em>{command.group}</em>
                <ArrowUpRight />
              </button>
            )
          })}
        </div>
        <div className="command-foot"><kbd>↑</kbd><kbd>↓</kbd> naviguer <kbd>↵</kbd> ouvrir <kbd>Échap</kbd> fermer</div>
      </div>
    </div>,
    document.body,
  )
}
