import React from 'react';
import { responseLabel, ruleSentence, RuleResponse } from '../../logic/rules';

const CHIP: Record<RuleResponse, React.CSSProperties> = {
  allow: { color: '#86EFAC', background: 'rgba(34,197,94,0.12)', borderColor: 'rgba(34,197,94,0.35)' },
  ask: { color: '#FCD34D', background: 'rgba(245,158,11,0.12)', borderColor: 'rgba(245,158,11,0.35)' },
  block: { color: '#FCA5A5', background: 'rgba(239,68,68,0.12)', borderColor: 'rgba(239,68,68,0.35)' },
};

export const ResponseChip: React.FC<{ response?: string }> = ({ response }) => {
  const r = (['allow', 'ask', 'block'].includes(response ?? '') ? response : 'allow') as RuleResponse;
  return (
    <span
      data-response={r}
      className="inline-flex items-center px-2.5 py-0.5 rounded-full border text-[12px] font-semibold whitespace-nowrap"
      style={CHIP[r]}
    >
      {responseLabel(r)}
    </span>
  );
};

export const RuleSentence: React.FC<{
  rule: { agent_or_profile: string; action: string; target: string; response?: string };
}> = ({ rule }) => {
  const s = ruleSentence(rule);
  return (
    <span className="text-[15px] leading-relaxed text-[#E6E9EF]">
      {s.lead}{' '}
      <code className="font-mono text-[14px] text-[#BFDBFE] [overflow-wrap:anywhere]">{s.target}</code>: {s.outcome}.
    </span>
  );
};
