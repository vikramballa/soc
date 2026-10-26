import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Toaster } from './components/toast'
import { Spinner } from './components/ui'
import { AuthGate, RequirePerm } from './lib/auth'
import Login from './pages/Login'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const Incidents = lazy(() => import('./pages/Incidents'))
const IncidentDetail = lazy(() => import('./pages/IncidentDetail'))
const Alerts = lazy(() => import('./pages/Alerts'))
const Events = lazy(() => import('./pages/Events'))
const Assets = lazy(() => import('./pages/Assets'))
const Identities = lazy(() => import('./pages/Identities'))
const ThreatIntel = lazy(() => import('./pages/ThreatIntel'))
const Mitre = lazy(() => import('./pages/Mitre'))
const Rules = lazy(() => import('./pages/Rules'))
const MlAnalytics = lazy(() => import('./pages/MlAnalytics'))
const AiAnalyst = lazy(() => import('./pages/AiAnalyst'))
const Reports = lazy(() => import('./pages/Reports'))
const Integrations = lazy(() => import('./pages/Integrations'))
const Admin = lazy(() => import('./pages/Admin'))
const Account = lazy(() => import('./pages/Account'))

function FullPageLoader() {
  return (
    <div className="flex h-full items-center justify-center">
      <Spinner className="size-5" />
    </div>
  )
}

export default function App() {
  return (
    <>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/*"
          element={
            <AuthGate fallback={<FullPageLoader />}>
              <Layout>
                <Suspense fallback={<FullPageLoader />}>
                  <Routes>
                    <Route index element={<Dashboard />} />
                    <Route path="incidents" element={<Incidents />} />
                    <Route path="incidents/:id" element={<IncidentDetail />} />
                    <Route path="alerts" element={<Alerts />} />
                    <Route path="events" element={<RequirePerm perm="event:read"><Events /></RequirePerm>} />
                    <Route path="assets" element={<Assets />} />
                    <Route path="users" element={<Identities />} />
                    <Route path="threat-intel" element={<ThreatIntel />} />
                    <Route path="mitre" element={<Mitre />} />
                    <Route path="rules" element={<Rules />} />
                    <Route path="ml" element={<MlAnalytics />} />
                    <Route path="ai" element={<AiAnalyst />} />
                    <Route path="reports" element={<RequirePerm perm="report:generate"><Reports /></RequirePerm>} />
                    <Route path="integrations" element={<Integrations />} />
                    <Route path="account" element={<Account />} />
                    <Route path="admin" element={<RequirePerm perm="admin:manage"><Admin /></RequirePerm>} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                  </Routes>
                </Suspense>
              </Layout>
            </AuthGate>
          }
        />
      </Routes>
      <Toaster />
    </>
  )
}
