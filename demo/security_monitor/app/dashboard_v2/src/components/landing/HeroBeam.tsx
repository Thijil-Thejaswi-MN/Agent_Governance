import React from 'react';
import './HeroBeam.css';

export interface HeroBeamProps {
  prefersReducedMotion?: boolean;
}

export const HeroBeam: React.FC<HeroBeamProps> = ({ prefersReducedMotion = false }) => {
  return (
    <div className="hero-beam-wrapper" aria-hidden="true" data-testid="hero-beam">
      <div className={`hero-beam-glow ${prefersReducedMotion ? '' : 'hero-beam-animated'}`} />
      <div className={`hero-beam-halftone ${prefersReducedMotion ? '' : 'hero-beam-animated'}`} />
      <div className="hero-beam-vignette" />
    </div>
  );
};