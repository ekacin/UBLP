// Static reference lists for the New Submission form's dropdowns — kept as plain arrays rather
// than free-text inputs specifically to close the gaps a manual test surfaced: a currency field
// that accepted "USDa", and no structural place for delivery terms at all. Not exhaustive
// (ISO 4217/3166 both have far more entries) — covers the major trading nations/currencies,
// a reasonable v0.1 scope; a real deployment would want the full ISO lists.

export const CURRENCIES = [
  'USD', 'EUR', 'GBP', 'TRY', 'JPY', 'CNY', 'CHF', 'CAD', 'AUD', 'INR',
  'AED', 'SAR', 'QAR', 'KWD', 'BHD', 'OMR', 'JOD', 'ILS', 'EGP',
  'RUB', 'UAH', 'PLN', 'CZK', 'HUF', 'RON', 'BGN', 'SEK', 'NOK', 'DKK',
  'BRL', 'MXN', 'ARS', 'CLP', 'COP',
  'KRW', 'SGD', 'HKD', 'TWD', 'THB', 'VND', 'IDR', 'MYR', 'PHP', 'PKR', 'BDT',
  'ZAR', 'NGN', 'KES',
  'NZD',
] as const;

// Incoterms 2020's own two groups (any mode of transport, then sea/inland-waterway-only) —
// same 11 rules and same ordering as modules/incoterms-escrow's src/policies/*.ts, so an
// operator who knows one module's terms recognizes the other's list immediately.
export const INCOTERMS = [
  { code: 'EXW', label: 'EXW — Ex Works' },
  { code: 'FCA', label: 'FCA — Free Carrier' },
  { code: 'CPT', label: 'CPT — Carriage Paid To' },
  { code: 'CIP', label: 'CIP — Carriage and Insurance Paid To' },
  { code: 'DAP', label: 'DAP — Delivered at Place' },
  { code: 'DPU', label: 'DPU — Delivered at Place Unloaded' },
  { code: 'DDP', label: 'DDP — Delivered Duty Paid' },
  { code: 'FAS', label: 'FAS — Free Alongside Ship' },
  { code: 'FOB', label: 'FOB — Free On Board' },
  { code: 'CFR', label: 'CFR — Cost and Freight' },
  { code: 'CIF', label: 'CIF — Cost, Insurance and Freight' },
] as const;

export const WEIGHT_UNITS = ['kg', 'lb'] as const;

export const TRANSPORT_MODES = ['AIR', 'SEA', 'ROAD', 'RAIL'] as const;

// ISO 3166-1 alpha-2 — major trading nations across all regions, not the full ~195-entry list.
export const COUNTRIES: { code: string; name: string }[] = [
  { code: 'US', name: 'United States' },
  { code: 'CA', name: 'Canada' },
  { code: 'MX', name: 'Mexico' },
  { code: 'BR', name: 'Brazil' },
  { code: 'AR', name: 'Argentina' },
  { code: 'CL', name: 'Chile' },
  { code: 'CO', name: 'Colombia' },
  { code: 'GB', name: 'United Kingdom' },
  { code: 'DE', name: 'Germany' },
  { code: 'FR', name: 'France' },
  { code: 'IT', name: 'Italy' },
  { code: 'ES', name: 'Spain' },
  { code: 'NL', name: 'Netherlands' },
  { code: 'BE', name: 'Belgium' },
  { code: 'PL', name: 'Poland' },
  { code: 'CZ', name: 'Czech Republic' },
  { code: 'HU', name: 'Hungary' },
  { code: 'RO', name: 'Romania' },
  { code: 'BG', name: 'Bulgaria' },
  { code: 'GR', name: 'Greece' },
  { code: 'PT', name: 'Portugal' },
  { code: 'SE', name: 'Sweden' },
  { code: 'NO', name: 'Norway' },
  { code: 'DK', name: 'Denmark' },
  { code: 'FI', name: 'Finland' },
  { code: 'CH', name: 'Switzerland' },
  { code: 'AT', name: 'Austria' },
  { code: 'IE', name: 'Ireland' },
  { code: 'UA', name: 'Ukraine' },
  { code: 'RU', name: 'Russia' },
  { code: 'TR', name: 'Turkey' },
  { code: 'AE', name: 'United Arab Emirates' },
  { code: 'SA', name: 'Saudi Arabia' },
  { code: 'QA', name: 'Qatar' },
  { code: 'KW', name: 'Kuwait' },
  { code: 'IL', name: 'Israel' },
  { code: 'EG', name: 'Egypt' },
  { code: 'ZA', name: 'South Africa' },
  { code: 'NG', name: 'Nigeria' },
  { code: 'KE', name: 'Kenya' },
  { code: 'CN', name: 'China' },
  { code: 'JP', name: 'Japan' },
  { code: 'KR', name: 'South Korea' },
  { code: 'IN', name: 'India' },
  { code: 'PK', name: 'Pakistan' },
  { code: 'BD', name: 'Bangladesh' },
  { code: 'VN', name: 'Vietnam' },
  { code: 'TH', name: 'Thailand' },
  { code: 'ID', name: 'Indonesia' },
  { code: 'MY', name: 'Malaysia' },
  { code: 'PH', name: 'Philippines' },
  { code: 'SG', name: 'Singapore' },
  { code: 'TW', name: 'Taiwan' },
  { code: 'HK', name: 'Hong Kong' },
  { code: 'AU', name: 'Australia' },
  { code: 'NZ', name: 'New Zealand' },
];
