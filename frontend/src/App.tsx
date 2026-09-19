import { Link, Route, Routes } from 'react-router-dom'
import AppLayout from '@/components/layout/app-layout'
import LoginPage from '@/pages/login'
import SetupPage from '@/pages/setup'
import { OverviewPage, ProjectsPage } from '@/pages/projects'
import EntitiesPage from '@/pages/entities'
import ActivityPage from '@/pages/activity'
import { KeysPage, SettingsPage } from '@/pages/settings'
import OperatorsPage from '@/pages/operators'
import { ServiceAccountsPage, FederationPage, OAuthClientsPage, ProvisioningPage } from '@/pages/integrations'
import MembersPage from '@/pages/members'
import RoleAssignmentsPage from '@/pages/role-assignments'
import ApplicationDetailPage from '@/pages/application-detail'
import FederationDetailPage from '@/pages/federation-detail'
import NotificationsPage from '@/pages/notifications'
export default function App() {
  return <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/setup" element={<SetupPage />} />
    <Route element={<AppLayout />}>
      <Route index element={<OverviewPage />} />
      <Route path="projects" element={<ProjectsPage />} />
      <Route path="projects/:project" element={<ProjectsPage />} />
      <Route path="projects/:project/environments/:environment">
        {(['users', 'organizations', 'applications', 'resources', 'roles', 'grants'] as const).map(kind => <Route key={kind} path={kind} element={<EntitiesPage key={kind} kind={kind} />} />)}
        <Route path="organizations/:orgId/members" element={<MembersPage />} />
        <Route path="applications/:appId" element={<ApplicationDetailPage />} />
        <Route path="role-assignments" element={<RoleAssignmentsPage />} />
        <Route path="service-accounts" element={<ServiceAccountsPage />} />
        <Route path="federation" element={<FederationPage />} />
        <Route path="federation/:connectionId" element={<FederationDetailPage />} />
        <Route path="oauth-clients" element={<OAuthClientsPage />} />
        <Route path="provisioning" element={<ProvisioningPage />} />
        <Route path="notifications" element={<NotificationsPage />} />
        <Route path="sessions" element={<ActivityPage />} />
        <Route path="audit-events" element={<ActivityPage audit />} />
      </Route>
      <Route path="operators" element={<OperatorsPage />} />
      <Route path="keys" element={<KeysPage />} />
      <Route path="settings" element={<SettingsPage />} />
      <Route path="*" element={<div className="space-y-4"><h1 className="text-xl font-semibold">Page not found</h1><Link className="text-primary underline" to="/">Back to overview</Link></div>} />
    </Route>
  </Routes>
}
