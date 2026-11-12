import React, { Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { AppLayout } from './components/layout/AppLayout';

import { rootRedirect } from './logic/journey';

// Pages (the old marketing Home page, pages/HomePage.tsx, is kept but no longer routed)
const AskPage = React.lazy(() => import('./pages/AskPage').then(m => ({ default: m.AskPage })));
const WatchPage = React.lazy(() => import('./pages/WatchPage').then(m => ({ default: m.WatchPage })));
const FleetPage = React.lazy(() => import('./pages/FleetPage').then(m => ({ default: m.FleetPage })));
const HistoryPage = React.lazy(() => import('./pages/HistoryPage').then(m => ({ default: m.HistoryPage })));
const ResultsPage = React.lazy(() => import('./pages/ResultsPage').then(m => ({ default: m.ResultsPage })));

// v4 Role Pages
const AdminOverviewPage = React.lazy(() =>
  import('./pages/AdminOverviewPage').then(m => ({ default: m.AdminOverviewPage }))
);
const TeamLeadPage = React.lazy(() =>
  import('./pages/TeamLeadPage').then(m => ({ default: m.TeamLeadPage }))
);
const InboxPage = React.lazy(() =>
  import('./pages/InboxPage').then(m => ({ default: m.InboxPage }))
);
const RecordsPage = React.lazy(() =>
  import('./pages/RecordsPage').then(m => ({ default: m.RecordsPage }))
);
const StandingRulesPage = React.lazy(() =>
  import('./pages/StandingRulesPage').then(m => ({ default: m.StandingRulesPage }))
);
const IncidentsPage = React.lazy(() => import('./pages/IncidentsPage').then(m => ({ default: m.IncidentsPage })));
const ReportPage = React.lazy(() => import('./pages/ReportPage').then(m => ({ default: m.ReportPage })));
const SignInPage = React.lazy(() =>
  import('./pages/SignInPage').then(m => ({ default: m.SignInPage }))
);

const PageLoader: React.FC = () => (
  <div className="flex items-center justify-center min-h-[350px] text-[15px] text-[#8B95A7]">
    Loading…
  </div>
);

const page = (el: React.ReactNode) => <Suspense fallback={<PageLoader />}>{el}</Suspense>;

// /dashboard: sign-in without a session, otherwise the role's home (developer and admin: Run).
const RootRedirect: React.FC = () => {
  const { authChecked, hasToken, user } = useAuth();
  const to = rootRedirect({ authChecked, hasToken, role: user?.role ?? null });
  return to ? <Navigate to={to} replace /> : <PageLoader />;
};

const RunRedirect: React.FC = () => {
  const { taskId } = useParams<{ taskId: string }>();
  return <Navigate to={`/run/${taskId}`} replace />;
};

const TaskRedirect: React.FC = () => {
  const { taskId } = useParams<{ taskId: string }>();
  return <Navigate to={`/history/${taskId}`} replace />;
};

export const App: React.FC = () => {
  return (
    <AuthProvider>
      <BrowserRouter basename="/dashboard">
        <Routes>
          <Route element={<AppLayout />}>
            {/* One way in: sign-in, then the role's home */}
            <Route index element={<RootRedirect />} />

            {/* v4 Role Homes */}
            <Route path="signin" element={page(<SignInPage />)} />
            <Route path="overview" element={page(<AdminOverviewPage />)} />
            <Route path="team" element={page(<TeamLeadPage />)} />
            <Route path="inbox" element={page(<InboxPage />)} />
            <Route path="records" element={page(<RecordsPage />)} />
            <Route path="standing-rules" element={page(<StandingRulesPage />)} />

            {/* Developer Flow (Ask / Watch / Done demo) */}
            <Route path="run" element={page(<AskPage />)} />
            <Route path="run/:taskId" element={page(<WatchPage />)} />

            {/* Shared run investigation */}
            {/* The old investigation page (pages/RunInvestigationPage.tsx, kept, not routed) showed
                placeholder values; the Run page shows the same run from real data. */}
            <Route path="runs/:taskId" element={<RunRedirect />} />

            {/* Fleet, History, Results */}
            <Route path="fleet" element={page(<FleetPage />)} />
            <Route path="history" element={page(<HistoryPage />)} />
            <Route path="history/:taskId" element={page(<WatchPage readOnly />)} />
            <Route path="results" element={page(<ResultsPage />)} />
            <Route path="report/:taskId" element={page(<ReportPage />)} />
            <Route path="incidents" element={page(<IncidentsPage />)} />

            {/* v2 and v3 compatibility redirects */}
            <Route path="tasks" element={<Navigate to="/history" replace />} />
            <Route path="tasks/:taskId" element={<TaskRedirect />} />
            <Route path="approvals" element={<Navigate to="/fleet" replace />} />
            <Route path="activity" element={<Navigate to="/fleet" replace />} />
            <Route path="agents" element={<Navigate to="/fleet" replace />} />
            <Route path="evaluation" element={<Navigate to="/results" replace />} />
            <Route path="architecture" element={<Navigate to="/" replace />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
};
