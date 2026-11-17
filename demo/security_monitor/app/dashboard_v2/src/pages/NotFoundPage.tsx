import React from 'react';
import { useLocation, Link } from 'react-router-dom';
import { Home } from 'lucide-react';

export const NotFoundPage: React.FC = () => {
  const location = useLocation();

  return (
    <div className="relative flex flex-col items-center justify-center min-h-[calc(100vh-140px)] px-4 py-12 text-center overflow-hidden select-none">
      {/* Faint grid background */}
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-20"
        style={{
          backgroundImage: `
            repeating-linear-gradient(0deg, transparent, transparent 19px, rgba(59, 130, 246, 0.15) 19px, rgba(59, 130, 246, 0.15) 20px, transparent 20px, transparent 39px, rgba(59, 130, 246, 0.15) 39px, rgba(59, 130, 246, 0.15) 40px),
            repeating-linear-gradient(90deg, transparent, transparent 19px, rgba(59, 130, 246, 0.15) 19px, rgba(59, 130, 246, 0.15) 20px, transparent 20px, transparent 39px, rgba(59, 130, 246, 0.15) 39px, rgba(59, 130, 246, 0.15) 40px),
            radial-gradient(circle at 20px 20px, rgba(59, 130, 246, 0.25) 2px, transparent 2px),
            radial-gradient(circle at 40px 40px, rgba(59, 130, 246, 0.25) 2px, transparent 2px)
          `,
          backgroundSize: '40px 40px, 40px 40px, 40px 40px, 40px 40px',
          maskImage: 'radial-gradient(ellipse 65% 65% at 50% 50%, #000 20%, transparent 80%)',
          WebkitMaskImage: 'radial-gradient(ellipse 65% 65% at 50% 50%, #000 20%, transparent 80%)',
        }}
        aria-hidden="true"
      />

      <div className="relative z-10 mx-auto flex w-full max-w-lg flex-col items-center text-center">
        {/* Outlined dashed 404 SVG */}
        <svg
          viewBox="0 0 800 300"
          className="w-full max-w-[18rem] sm:max-w-md select-none"
          aria-hidden="true"
        >
          <text
            x="50%"
            y="50%"
            textAnchor="middle"
            dominantBaseline="middle"
            fill="rgba(59, 130, 246, 0.08)"
            stroke="#3B82F6"
            strokeWidth="2.5"
            strokeDasharray="40 20"
            className="font-black tracking-tighter"
            style={{ fontSize: '20rem' }}
          >
            404
          </text>
        </svg>

        {/* Visually hidden 404 for screen readers */}
        <span className="sr-only">404</span>

        <div className="mt-4 flex flex-col items-center gap-2">
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-[#E6E9EF]">
            This page doesn't exist.
          </h1>
          <p className="text-[#8B95A7] text-[13px] sm:text-[14px] leading-relaxed max-w-sm sm:max-w-md mx-auto">
            The address{' '}
            <code
              title={location.pathname}
              className="inline-block max-w-[200px] sm:max-w-xs align-bottom truncate font-mono text-[12px] sm:text-[13px] px-1.5 py-0.5 rounded bg-[#11151D] border border-[#2A3344] text-[#E6E9EF]"
            >
              {location.pathname}
            </code>{' '}
            isn't part of the console. It may have moved, or the link was typed wrong.
          </p>
        </div>

        <Link
          to="/"
          className="mt-6 inline-flex items-center justify-center gap-2 min-h-[44px] px-6 rounded-xl bg-[#2563EB] hover:bg-[#1D4ED8] focus:outline-none focus:ring-2 focus:ring-[#3B82F6] focus:ring-offset-2 focus:ring-offset-[#0B0E14] text-white font-medium text-[14px] transition-colors no-underline shadow-sm cursor-pointer"
        >
          <Home className="w-4 h-4" aria-hidden="true" />
          <span>Go back home</span>
        </Link>
      </div>
    </div>
  );
};

export default NotFoundPage;
