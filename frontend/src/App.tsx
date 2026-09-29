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
import OrganizationLayout from '@/pages/organization-layout'
import { OrganizationConnections, OrganizationOverview } from '@/pages/organization-overview'
import UserDetailPage from '@/pages/user-detail'
import { GroupDetailPage, GroupsPage } from '@/pages/groups'
import { DomainsPage } from '@/pages/domains'
import { InvitationsPage } from '@/pages/invitations'
import RoleAssignmentsPage from '@/pages/role-assignments'
import ApplicationDetailPage from '@/pages/application-detail'
import FederationDetailPage from '@/pages/federation-detail'
import NotificationsPage from '@/pages/notifications'
import HostedLoginPage from '@/pages/hosted-login'
import EnvironmentHomePage from '@/pages/environment-home'
import OAuthClientDetailPage from '@/pages/oauth-client-detail'
import BrandingEditorPage from '@/pages/branding-editor'
import PasswordPolicyPage from '@/pages/password-policy'
import SignInPolicyPage from '@/pages/sign-in-policy'
export default function App() {
  return <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/setup" element={<SetupPage />} />
    <Route element={<AppLayout />}>
      <Route index element={<OverviewPage />} />
      <Route path="projects" element={<ProjectsPage />} />
      <Route path="projects/:project" element={<ProjectsPage />} />
      <Route path="projects/:project/environments/:environment">
        <Route index element={<EnvironmentHomePage />} />
        {(['users', 'organizations', 'applications', 'resources', 'roles', 'grants'] as const).map(kind => <Route key={kind} path={kind} element={<EntitiesPage key={kind} kind={kind} />} />)}
        <Route path="organizations/:orgId" element={<OrganizationLayout />}>
          <Route index element={<OrganizationOverview />} />
          <Route path="members" element={<MembersPage />} />
          <Route path="groups" element={<GroupsPage />} />
          <Route path="groups/:groupId" element={<GroupDetailPage />} />
          <Route path="domains" element={<DomainsPage />} />
          <Route path="invitations" element={<InvitationsPage />} />
          <Route path="connections" element={<OrganizationConnections />} />
        </Route>
        <Route path="users/:userId" element={<UserDetailPage />} />
        <Route path="applications/:appId" element={<ApplicationDetailPage />} />
        <Route path="role-assignments" element={<RoleAssignmentsPage />} />
        <Route path="service-accounts" element={<ServiceAccountsPage />} />
        <Route path="federation" element={<FederationPage />} />
        <Route path="federation/:connectionId" element={<FederationDetailPage />} />
        <Route path="oauth-clients" element={<OAuthClientsPage />} />
        <Route path="oauth-clients/:clientId" element={<OAuthClientDetailPage />} />
        <Route path="provisioning" element={<ProvisioningPage />} />
        <Route path="notifications" element={<NotificationsPage />} />
        <Route path="hosted-login" element={<HostedLoginPage />} />
        <Route path="password-policy" element={<PasswordPolicyPage />} />
        <Route path="sign-in-policy" element={<SignInPolicyPage />} />
        <Route path="hosted-login/default" element={<BrandingEditorPage key="default" />} />
        <Route path="hosted-login/clients/:clientId" element={<BrandingEditorPage />} />
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
