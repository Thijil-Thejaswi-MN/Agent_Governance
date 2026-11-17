import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { Eyebrow } from './Eyebrow';
import { Star, Shield, Sparkles } from 'lucide-react';

describe('Eyebrow component', () => {
  it('renders text and decorative icon with aria-hidden', () => {
    const html = renderToStaticMarkup(
      <Eyebrow text="WHAT IT DOES" icon={Sparkles} id="eyebrow-features" />
    );

    expect(html).toContain('WHAT IT DOES');
    expect(html).toContain('id="eyebrow-features"');
    expect(html).toContain('aria-hidden="true"');
    expect(html).toContain('rounded-full');
  });

  it('renders each required landing eyebrow label', () => {
    const html1 = renderToStaticMarkup(<Eyebrow text="WHAT IT DOES" icon={Sparkles} />);
    const html2 = renderToStaticMarkup(<Eyebrow text="FROM OUR EVALUATION" icon={Shield} />);
    const html3 = renderToStaticMarkup(<Eyebrow text="ROLES" icon={Star} />);

    expect(html1).toContain('WHAT IT DOES');
    expect(html2).toContain('FROM OUR EVALUATION');
    expect(html3).toContain('ROLES');
  });

  it('contains no banned words in copy', () => {
    const html = renderToStaticMarkup(
      <div>
        <Eyebrow text="WHAT IT DOES" />
        <Eyebrow text="FROM OUR EVALUATION" />
        <Eyebrow text="ROLES" />
      </div>
    );

    const bannedWords = ['safe', 'secure', 'securely', 'guaranteed', 'tamper-proof', 'first', 'complete', 'signed'];
    for (const word of bannedWords) {
      expect(html.toLowerCase()).not.toMatch(new RegExp(`\\b${word}\\b`));
    }
  });
});