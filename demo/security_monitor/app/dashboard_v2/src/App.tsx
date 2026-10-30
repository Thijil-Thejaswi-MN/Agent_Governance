import React, { Suspense } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { AppLayout } from './components/layout/AppLayout';

// Route-level code splitting via React.lazy
const HomePage = React.lazy(() => import('./pages/HomePage').then(m => ({ default: m.HomePage })));
const AskPage = React.lazy(() => import('./pages/AskPage').then(m => ({ default: m.AskPage })));
const WatchPage = React.lazy(() => import('./pages/WatchPage').then(m => ({ default: m.WatchPage })));
const FleetPage = React.lazy(() => import('./pages/FleetPage').then(m => ({ default: m.FleetPage })));
const HistoryPage = React.lazy(() => import('./pages/HistoryPage').then(m => ({ default: m.HistoryPage })));
const ResultsPage = React.lazy(() => import('./pages/ResultsPage').then(m => ({ default: m.ResultsPage })));

const PageLoader: React.FC = () => (
  <div className="flex items-center justify-center min-h-[350px] text-[15px]" style={{ color: 'var(--text-2)' }}>
    Loading…
  </div>
);

const page = (el: React.ReactNode) => <Suspense fallback={<PageLoader />}>{el}</Suspense>;

// Old v2 links keep working.
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
            <Route index element={page(<HomePage />)} />
            <Route path="run" element={page(<AskPage />)} />
            <Route path="run/:taskId" element={page(<WatchPage />)} />
            <Route path="fleet" element={page(<FleetPage />)} />
            <Route path="history" element={page(<HistoryPage />)} />
            <Route path="history/:taskId" element={page(<WatchPage readOnly />)} />
            <Route path="results" element={page(<ResultsPage />)} />

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
