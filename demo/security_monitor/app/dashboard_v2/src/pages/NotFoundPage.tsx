import React from 'react';
import { useLocation, Link } from 'react-router-dom';
import { Home } from 'lucide-react';
import { PageHeader } from '../components/ui/PageHeader';

export const NotFoundPage: React.FC = () => {
  const location = useLocation();

  return (
    <div className="relative flex flex-col items-center justify-center min-h-[calc(100vh-4rem)] -mx-4 -my-6 md:-m-8 px-4 py-12 text-center overflow-hidden select-none bg-[#0A0D12]">
      {/* Soft blue glow behind the 404 */}
      <div
        className="pointer-events-none absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[300px] sm:w-[680px] sm:h-[380px] bg-blue-500/10 blur-[130px] rounded-full z-0"
        aria-hidden="true"
      />

      {/* Edge-to-edge fine square grid with dots at line crossings */}
      <div
        data-testid="not-found-grid"
        className="pointer-events-none absolute inset-0 z-0"
        style={{
          backgroundImage: `
            repeating-linear-gradient(0deg, transparent, transparent 19px, rgba(96, 165, 250, 0.10) 19px, rgba(96, 165, 250, 0.10) 20px, transparent 20px, transparent 39px, rgba(96, 165, 250, 0.10) 39px, rgba(96, 165, 250, 0.10) 40px),
            repeating-linear-gradient(90deg, transparent, transparent 19px, rgba(96, 165, 250, 0.10) 19px, rgba(96, 165, 250, 0.10) 20px, transparent 20px, transparent 39px, rgba(96, 165, 250, 0.10) 39px, rgba(96, 165, 250, 0.10) 40px),
            radial-gradient(circle at 20px 20px, rgba(96, 165, 250, 0.22) 2px, transparent 2px),
            radial-gradient(circle at 40px 40px, rgba(96, 165, 250, 0.22) 2px, transparent 2px)
          `,
          backgroundSize: '40px 40px, 40px 40px, 40px 40px, 40px 40px',
          maskImage: 'radial-gradient(ellipse 90% 90% at 50% 50%, #000 65%, transparent 100%)',
          WebkitMaskImage: 'radial-gradient(ellipse 90% 90% at 50% 50%, #000 65%, transparent 100%)',
        }}
        aria-hidden="true"
      />

      <div className="relative z-10 mx-auto flex w-full max-w-2xl flex-col items-center text-center">
        {/* Outlined dashed 404 SVG */}
        <svg
          viewBox="0 0 800 300"
          className="w-full max-w-[20rem] sm:max-w-lg md:max-w-xl select-none mx-auto"
          aria-hidden="true"
        >
          <text
            x="50%"
            y="50%"
            textAnchor="middle"
            dominantBaseline="middle"
            fill="rgba(59, 130, 246, 0.18)"
            stroke="#60A5FA"
            strokeWidth="2.5"
            strokeDasharray="40 20"
            className="font-black tracking-tighter not-found-dash"
            style={{ fontSize: '20rem' }}
          >
            404
          </text>
        </svg>

        {/* Visually hidden 404 for screen readers */}
        <span className="sr-only">404</span>

        <div className="mt-4 max-w-lg mx-auto">
          <PageHeader
            title="This page doesn't exist."
            className="text-center items-center"
            subtitle={
              <p className="text-[#8B95A7] text-[13px] sm:text-[14px] leading-relaxed max-w-sm sm:max-w-md mx-auto m-0">
                The address{' '}
                <code
                  title={location.pathname}
                  className="inline-block max-w-[200px] sm:max-w-xs align-bottom truncate font-mono text-[12px] sm:text-[13px] px-1.5 py-0.5 rounded bg-[#11151D] border border-[#2A3344] text-[#E6E9EF]"
                >
                  {location.pathname}
                </code>{' '}
                isn't part of the console. It may have moved, or the link was typed wrong.
              </p>
            }
          />
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
