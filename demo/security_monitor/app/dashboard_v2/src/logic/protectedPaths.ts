export const PROTECTED_PATHS = [
  '/overview',
  '/team',
  '/inbox',
  '/records',
  '/standing-rules',
  '/run',
  '/runs',
  '/fleet',
  '/history',
  '/evidence',
  '/report',
  '/conversations',
  '/incidents',
  '/inventory',
];

export const isProtectedPath = (path: string): boolean => {
  const normalized = path.startsWith('/') ? path : `/${path}`;
  return PROTECTED_PATHS.some(p => normalized === p || normalized.startsWith(`${p}/`));
};
