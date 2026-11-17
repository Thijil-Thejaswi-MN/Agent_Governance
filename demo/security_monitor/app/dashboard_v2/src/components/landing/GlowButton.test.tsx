import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { GlowButton } from './GlowButton';

describe('GlowButton component', () => {
  it('renders solid variant as button with custom id, type and text', () => {
    const html = renderToStaticMarkup(
      <GlowButton id="sign-in-submit-btn" type="submit" variant="solid">
        Sign in
      </GlowButton>
    );

    expect(html).toContain('id="sign-in-submit-btn"');
    expect(html).toContain('type="submit"');
    expect(html).toContain('Sign in');
    expect(html).toContain('bg-gradient-to-r');
    expect(html).toContain('min-h-[44px]');
  });

  it('renders disabled state correctly for solid variant', () => {
    const html = renderToStaticMarkup(
      <GlowButton id="sign-in-submit-btn" variant="solid" disabled>
        Signing in…
      </GlowButton>
    );

    expect(html).toContain('disabled=""');
    expect(html).toContain('disabled:opacity-50');
    expect(html).toContain('disabled:cursor-not-allowed');
    expect(html).toContain('Signing in…');
  });

  it('renders outline variant as an anchor link to #features', () => {
    const html = renderToStaticMarkup(
      <GlowButton variant="outline" href="#features" id="see-how-it-works-btn">
        See how it works
      </GlowButton>
    );

    expect(html).toContain('<a');
    expect(html).toContain('href="#features"');
    expect(html).toContain('id="see-how-it-works-btn"');
    expect(html).toContain('See how it works');
    expect(html).toContain('min-h-[44px]');
  });

  it('contains no banned words in copy', () => {
    const htmlSolid = renderToStaticMarkup(
      <GlowButton variant="solid">Sign in</GlowButton>
    );
    const htmlOutline = renderToStaticMarkup(
      <GlowButton variant="outline" href="#features">See how it works</GlowButton>
    );

    const bannedWords = ['safe', 'secure', 'securely', 'guaranteed', 'tamper-proof', 'first', 'complete', 'signed'];
    for (const word of bannedWords) {
      expect(htmlSolid.toLowerCase()).not.toMatch(new RegExp(`\\b${word}\\b`));
      expect(htmlOutline.toLowerCase()).not.toMatch(new RegExp(`\\b${word}\\b`));
    }
  });
});