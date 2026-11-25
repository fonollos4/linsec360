import {
  Activity,
  Boxes,
  FileCode2,
  HardDrive,
  LayoutDashboard,
  Play,
  Radar,
  Settings as SettingsIcon,
  ShieldCheck,
  UserRound,
  type LucideIcon,
} from 'lucide-react'

export type NavItem = { to: string; label: string; icon: LucideIcon }

export const navGroups: Array<{ label: string; items: NavItem[] }> = [
  {
    label: 'Pilotage',
    items: [
      { to: '/', label: 'Vue d’ensemble', icon: LayoutDashboard },
      { to: '/hosts', label: 'Hôtes', icon: HardDrive },
    ],
  },
  {
    label: 'Automatisation',
    items: [
      { to: '/deployments', label: 'Déploiements', icon: Play },
      { to: '/playbooks', label: 'Playbooks', icon: FileCode2 },
    ],
  },
  {
    label: 'Sécurité',
    items: [
      { to: '/compliance', label: 'Conformité', icon: ShieldCheck },
      { to: '/patching', label: 'Correctifs', icon: Boxes },
      { to: '/detection', label: 'Détection', icon: Radar },
    ],
  },
  {
    label: 'Système',
    items: [
      { to: '/audit', label: 'Audit', icon: Activity },
      { to: '/profile', label: 'Profil', icon: UserRound },
      { to: '/settings', label: 'Paramètres', icon: SettingsIcon },
    ],
  },
]
