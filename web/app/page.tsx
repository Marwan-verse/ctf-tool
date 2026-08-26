'use client';

import { type CSSProperties, type DragEvent, type FormEvent, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';

type Profile = 'quick' | 'balanced' | 'deep';
type EvidenceSection = 'image' | 'audio';
type Screen = 'setup' | 'running' | 'results';
type ResultTab = 'overview' | 'audio' | 'candidates' | 'artifacts' | 'visual' | 'metadata' | 'hex' | 'tools' | 'methods';
type MethodFilter = 'all' | 'completed' | 'missing' | 'skipped' | 'failed';
type BooleanOptionKey = 'structure_analysis' | 'visual_analysis' | 'lsb_analysis' | 'ocr' | 'barcodes' | 'recursive_extraction' | 'decoders' | 'crypto_analysis' | 'repairs' | 'external_tools' | 'external_extraction' | 'audio_spectrogram' | 'audio_signal_decoders' | 'audio_sstv' | 'audio_channel_exports' | 'audio_audacity_bundle';

type ScanOptions = {
  structure_analysis: boolean;
  visual_analysis: boolean;
  lsb_analysis: boolean;
  ocr: boolean;
  barcodes: boolean;
  recursive_extraction: boolean;
  decoders: boolean;
  crypto_analysis: boolean;
  repairs: boolean;
  external_tools: boolean;
  external_extraction: boolean;
  evidence_type: 'auto' | 'image' | 'audio';
  audio_spectrogram: boolean;
  audio_signal_decoders: boolean;
  audio_sstv: boolean;
  audio_channel_exports: boolean;
  audio_audacity_bundle: boolean;
  audio_analysis_seconds: number;
  audio_spectrogram_fft: 256 | 512 | 1024 | 2048 | 4096;
  audio_channel_mode: 'mix' | 'left' | 'right' | 'difference';
  audio_lsb_bits: number;
  max_recursion_depth: number;
  max_artifacts: number;
  tool_timeout_seconds: number;
  external_output_kib: number;
  max_external_files: number;
  foremost_depth: number;
  color_remap_variants: number;
  zsteg_mode: 'all' | 'lsb';
  ocr_language: string;
  selected_external_tools: string[] | null;
};

type Candidate = {
  id?: string;
  value?: string;
  text?: string;
  raw?: string;
  confidence?: number | string;
  score?: number;
  confidence_band?: string;
  source?: string;
  source_artifact_id?: string;
  method?: string;
  evidence?: string | Record<string, unknown>;
  reasons?: string[];
  offset?: number;
  transform_chain?: string[];
  occurrences?: Array<{
    artifact_id?: string;
    method?: string;
    offset?: number | null;
    transform_chain?: string[];
    context?: string;
  }>;
};

type Artifact = {
  id?: string;
  artifact_id?: string;
  name?: string;
  logical_name?: string;
  filename?: string;
  mime_type?: string;
  media_type?: string;
  detected_type?: string;
  kind?: string;
  type?: string;
  size?: number;
  size_bytes?: number;
  sha256?: string;
  parent_id?: string | null;
  depth?: number;
  origin?: string;
  method?: string;
  preview_url?: string;
  download_url?: string;
  metadata?: Record<string, unknown>;
};

type MethodRun = {
  id?: string;
  tool_id?: string;
  name?: string;
  title?: string;
  status?: string;
  summary?: string;
  version?: string;
  duration_ms?: number;
  findings?: number;
  error?: string;
  stdout?: string;
  stderr?: string;
  command?: string[];
  artifact_ids?: string[];
  extracted_count?: number;
  output_truncated?: boolean;
  category?: string;
  tool?: { executable?: string; resolved?: string | null; version?: string | null };
  details?: Record<string, unknown>;
};

type HexRow = { offset: number; hex: string; ascii: string; length: number };
type HexMatch = { offset: number; length: number };
type HexAnomaly = { kind: string; title: string; description: string; offset: number; length: number; severity?: string; details?: Record<string, unknown> };
type HexView = {
  artifact?: Artifact;
  offset: number;
  length: number;
  total_size: number;
  rows: HexRow[];
  matches: HexMatch[];
  anomalies: HexAnomaly[];
  search?: { query?: string; mode?: string; byte_length?: number; match_count?: number };
  anomaly_scan?: { enabled?: boolean; count?: number; bounded?: boolean };
};

type Finding = {
  id?: string;
  category?: string;
  title?: string;
  summary?: string;
  evidence?: string;
  description?: string;
  severity?: string;
  confidence?: number | string;
  offset?: number;
  artifact_id?: string;
  method?: string;
  method_id?: string;
};

type VisualView = {
  id?: string;
  artifact_id?: string;
  name?: string;
  title?: string;
  kind?: string;
  category?: string;
  relative_path?: string;
  width?: number;
  height?: number;
  preview_url?: string;
};

type AnalysisResult = {
  summary?: Record<string, unknown>;
  input?: Record<string, unknown>;
  candidates?: Candidate[];
  flag_candidates?: Candidate[];
  artifacts?: Artifact[];
  options?: ScanOptions;
  findings?: Finding[];
  methods?: MethodRun[];
  coverage?: MethodRun[] | Record<string, unknown>;
  visual_views?: VisualView[];
  metadata?: Record<string, unknown> | Array<Record<string, unknown>>;
  structure?: unknown;
  logs?: unknown[];
  section?: EvidenceSection;
  audio_analysis?: {
    metadata?: { properties?: Record<string, unknown>; statistics?: Record<string, unknown>; container?: Record<string, unknown> };
    signals?: {
      frequency_peaks?: Array<{ frequency_hz?: number; relative_db?: number }>;
      silent_segments?: Array<{ start_seconds?: number; end_seconds?: number; duration_seconds?: number }>;
      ultrasonic_energy_ratio?: number;
      dtmf?: { symbols?: string; events?: Array<Record<string, unknown>> };
      morse?: { text?: string; pattern?: string; events?: Array<Record<string, unknown>> };
      sstv?: { candidate?: boolean; leader_frames?: number; sync_frames?: number; sync_offsets_seconds?: number[]; method?: string };
    };
  };
  [key: string]: unknown;
};

type Job = {
  id?: string;
  job_id?: string;
  status: string;
  profile?: Profile;
  original_filename?: string;
  original_name?: string;
  filename?: string;
  size?: number;
  size_bytes?: number;
  sha256?: string;
  input_sha256?: string;
  progress?: number;
  options?: ScanOptions;
  stage?: string;
  current_stage?: string;
  message?: string;
  created_at?: string;
  updated_at?: string;
  result?: AnalysisResult | null;
  artifacts?: Artifact[];
  error?: string | Record<string, string> | null;
  [key: string]: unknown;
};

type Capability = { id?: string; name?: string; executable?: string; available?: boolean; resolved?: string | null; source?: string | null; version?: string; category?: string; profiles?: string[]; formats?: string[]; install_hint?: string; installable?: boolean; install_strategy?: string | null };
type ToolInstallReport = { status?: string; installed_count?: number; already_available_count?: number; available_count?: number; requested_count?: number; unresolved_count?: number; managers?: string[]; message?: string; items?: Array<{ id?: string; status?: string; message?: string; channel?: string | null; source?: string | null; resolved?: string | null; diagnostic?: string | null }> };
type ActivityItem = { at: string; message: string; stage?: string };
type MetadataRow = { path: string; value: string };

const API_BASE = (
  process.env.NEXT_PUBLIC_API_URL
  || (typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:8000` : 'http://localhost:8000')
).replace(/\/$/, '');
const TERMINAL = new Set(['completed', 'succeeded', 'partial', 'failed', 'cancelled', 'expired']);
const profileOptionDefaults: Record<Profile, ScanOptions> = {
  quick: { structure_analysis: true, visual_analysis: true, lsb_analysis: true, ocr: true, barcodes: true, recursive_extraction: true, decoders: true, crypto_analysis: true, repairs: true, external_tools: true, external_extraction: true, evidence_type: 'auto', audio_spectrogram: true, audio_signal_decoders: true, audio_sstv: true, audio_channel_exports: true, audio_audacity_bundle: true, audio_analysis_seconds: 60, audio_spectrogram_fft: 1024, audio_channel_mode: 'mix', audio_lsb_bits: 1, max_recursion_depth: 2, max_artifacts: 45, tool_timeout_seconds: 20, external_output_kib: 512, max_external_files: 16, foremost_depth: 1, color_remap_variants: 4, zsteg_mode: 'all', ocr_language: 'eng', selected_external_tools: null },
  balanced: { structure_analysis: true, visual_analysis: true, lsb_analysis: true, ocr: true, barcodes: true, recursive_extraction: true, decoders: true, crypto_analysis: true, repairs: true, external_tools: true, external_extraction: true, evidence_type: 'auto', audio_spectrogram: true, audio_signal_decoders: true, audio_sstv: true, audio_channel_exports: true, audio_audacity_bundle: true, audio_analysis_seconds: 180, audio_spectrogram_fft: 2048, audio_channel_mode: 'mix', audio_lsb_bits: 2, max_recursion_depth: 3, max_artifacts: 100, tool_timeout_seconds: 60, external_output_kib: 1024, max_external_files: 32, foremost_depth: 2, color_remap_variants: 8, zsteg_mode: 'all', ocr_language: 'eng', selected_external_tools: null },
  deep: { structure_analysis: true, visual_analysis: true, lsb_analysis: true, ocr: true, barcodes: true, recursive_extraction: true, decoders: true, crypto_analysis: true, repairs: true, external_tools: true, external_extraction: true, evidence_type: 'auto', audio_spectrogram: true, audio_signal_decoders: true, audio_sstv: true, audio_channel_exports: true, audio_audacity_bundle: true, audio_analysis_seconds: 300, audio_spectrogram_fft: 4096, audio_channel_mode: 'mix', audio_lsb_bits: 4, max_recursion_depth: 4, max_artifacts: 220, tool_timeout_seconds: 180, external_output_kib: 2048, max_external_files: 64, foremost_depth: 4, color_remap_variants: 8, zsteg_mode: 'all', ocr_language: 'eng', selected_external_tools: null },
};
const configurableMethods: Array<{ key: BooleanOptionKey; title: string; copy: string }> = [
  { key: 'structure_analysis', title: 'Structure & metadata', copy: 'Chunks, markers, EXIF, comments, trailers and embedded objects.' },
  { key: 'visual_analysis', title: 'Pixel laboratory', copy: 'Safe previews, channels, frames, bit planes and pixel statistics.' },
  { key: 'lsb_analysis', title: 'LSB stream extraction', copy: 'Channel orders, bit positions and byte packing permutations.' },
  { key: 'ocr', title: 'OCR', copy: 'Tesseract across contrast, threshold and rotated variants.' },
  { key: 'barcodes', title: 'Barcode & QR decoding', copy: 'ZBar and OpenCV QR cross-checks.' },
  { key: 'recursive_extraction', title: 'Carving & recursion', copy: 'Embedded signatures, archives and nested image structures.' },
  { key: 'decoders', title: 'Encoding decoders', copy: 'Base encodings and bounded compression chains.' },
  { key: 'crypto_analysis', title: 'Encrypted payload recovery', copy: 'Detect ciphertext signals and try a supplied passphrase on bounded payloads.' },
  { key: 'repairs', title: 'Repair candidates', copy: 'Hashed repair copies while preserving the original.' },
  { key: 'external_tools', title: 'External CLI tools', copy: 'Run installed command-line analyzers in bounded subprocesses.' },
  { key: 'external_extraction', title: 'External payload extraction', copy: 'Allow password-gated stego tools to write bounded child artifacts.' },
];
const methodGroups = [
  { title: 'Metadata', copy: 'EXIF, XMP, IPTC, ICC', tone: 1 },
  { title: 'Structure', copy: 'Chunks, markers, trailers', tone: 2 },
  { title: 'Steganography', copy: 'LSB, channels, JPEG', tone: 3 },
  { title: 'Vision', copy: 'OCR and barcodes', tone: 4 },
];
const audioConfigurableMethods: Array<{ key: BooleanOptionKey; title: string; copy: string }> = [
  { key: 'structure_analysis', title: 'Container & metadata', copy: 'RIFF chunks, codec streams, tags, declared sizes and appended bytes.' },
  { key: 'visual_analysis', title: 'Waveform laboratory', copy: 'Bounded waveform, signal statistics, phase and channel inspection.' },
  { key: 'audio_spectrogram', title: 'Spectrograms', copy: 'Built-in STFT plus FFmpeg and SoX visual cross-checks when installed.' },
  { key: 'lsb_analysis', title: 'PCM sample bits', copy: 'Extract the configured least-significant sample bit planes.' },
  { key: 'audio_signal_decoders', title: 'Tone & modem decoders', copy: 'DTMF, Morse, frequency peaks, minimodem and multimon-ng.' },
  { key: 'audio_sstv', title: 'SSTV scan', copy: 'RX-SSTV-style 1900 Hz leader and 1200 Hz sync detection.' },
  { key: 'audio_channel_exports', title: 'Channel isolation', copy: 'Mono, left, right and stereo-difference review WAVs.' },
  { key: 'audio_audacity_bundle', title: 'Audacity handoff', copy: 'Normalized/reversed PCM WAVs and an importable label track.' },
  { key: 'recursive_extraction', title: 'Carving & recursion', copy: 'Embedded signatures, appended archives and recovered media.' },
  { key: 'decoders', title: 'Encoding decoders', copy: 'Tags, modem text and recovered strings through bounded transforms.' },
  { key: 'crypto_analysis', title: 'Encrypted payload recovery', copy: 'Inspect extracted sample-bit and carved data with a supplied key.' },
  { key: 'external_tools', title: 'External audio tools', copy: 'FFmpeg, SoX, FFprobe, MediaInfo and modem adapters.' },
  { key: 'external_extraction', title: 'External output artifacts', copy: 'Allow tools to create bounded spectrograms and PCM review files.' },
];
const audioMethodGroups = [
  { title: 'Spectrum', copy: 'Waveform and spectrogram', tone: 1 },
  { title: 'Signals', copy: 'DTMF, Morse and SSTV', tone: 2 },
  { title: 'Steganography', copy: 'PCM bits and channel phase', tone: 3 },
  { title: 'Review', copy: 'Audacity WAVs and labels', tone: 4 },
];
const profiles: Array<{ id: Profile; symbol: string; name: string; copy: string; tag: string }> = [
  { id: 'quick', symbol: '↯', name: 'Quick', copy: 'Core clues with minimal transforms', tag: 'Fast' },
  { id: 'balanced', symbol: '✦', name: 'Balanced', copy: 'Best coverage for most CTFs', tag: 'Recommended' },
  { id: 'deep', symbol: '◎', name: 'Deep', copy: 'Carving, recursion and repairs', tag: 'Thorough' },
];
const resultTabs: Array<{ id: ResultTab; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'audio', label: 'Audio lab' },
  { id: 'candidates', label: 'Flag candidates' },
  { id: 'artifacts', label: 'Artifacts' },
  { id: 'visual', label: 'Visual lab' },
  { id: 'metadata', label: 'Metadata' },
  { id: 'hex', label: 'Hex view' },
  { id: 'tools', label: 'Tool results' },
  { id: 'methods', label: 'Coverage & logs' },
];

function getJobId(job: Job | null) { return job?.id || job?.job_id || ''; }
function jobName(job: Job | null) { return job?.original_filename || job?.original_name || job?.filename || ''; }
function getCandidates(result?: AnalysisResult | null) { return result?.candidates || result?.flag_candidates || []; }
function getArtifacts(result?: AnalysisResult | null) { return result?.artifacts || []; }
function getMethods(result?: AnalysisResult | null) {
  if (result?.methods) return result.methods;
  if (Array.isArray(result?.coverage)) return result.coverage;
  return [];
}
function getVisuals(result?: AnalysisResult | null) { return result?.visual_views || []; }
function candidateValue(candidate: Candidate) { return candidate.value || candidate.text || candidate.raw || 'Unreadable candidate'; }
function artifactId(artifact: Artifact) { return artifact.id || artifact.artifact_id || ''; }
function artifactName(artifact: Artifact) { return artifact.logical_name || artifact.name || artifact.filename || `Artifact ${artifactId(artifact).slice(0, 8)}`; }
function artifactSize(artifact: Artifact) { return artifact.size_bytes ?? artifact.size ?? 0; }
function artifactMediaType(artifact: Artifact) { return artifact.media_type || artifact.mime_type || artifact.detected_type || artifact.kind || artifact.type || 'binary'; }
function artifactDepth(artifact: Artifact) {
  const nested = artifact.metadata?.depth;
  return artifact.depth ?? (typeof nested === 'number' ? nested : 0);
}
function artifactOrigin(artifact: Artifact) {
  if (artifact.origin || artifact.method) return artifact.origin || artifact.method;
  const lineage = artifact.metadata?.lineage;
  if (Array.isArray(lineage) && lineage[0] && typeof lineage[0] === 'object') {
    const producer = (lineage[0] as Record<string, unknown>).producer;
    if (typeof producer === 'string') return producer;
  }
  return artifact.kind === 'original' ? 'Immutable source' : 'Extracted evidence';
}
function methodName(method: MethodRun) { return method.title || method.name || method.tool_id || 'Analyzer'; }
function formatBytes(value?: number) {
  if (value === undefined || Number.isNaN(value)) return '—';
  if (value < 1024) return `${value} B`;
  const units = ['KB', 'MB', 'GB'];
  let size = value / 1024;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) { size /= 1024; index += 1; }
  return `${size.toFixed(size >= 10 ? 1 : 2)} ${units[index]}`;
}
function formatHexOffset(value: number) {
  return `0x${Math.max(0, Math.floor(value)).toString(16).padStart(8, '0')}`;
}
function formatDuration(ms?: number) {
  if (ms === undefined) return '—';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(ms > 10000 ? 0 : 1)} s`;
}
function formatDate(value?: string) {
  if (!value) return 'Just now';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });
}
function scoreOf(candidate: Candidate) {
  if (typeof candidate.score === 'number' && Number.isFinite(candidate.score)) return Math.max(0, Math.min(100, Math.round(candidate.score)));
  if (typeof candidate.confidence === 'number') return candidate.confidence <= 1 ? Math.round(candidate.confidence * 100) : Math.round(candidate.confidence);
  if (typeof candidate.confidence === 'string') {
    const parsed = Number(candidate.confidence.replace('%', ''));
    if (!Number.isNaN(parsed)) return parsed <= 1 ? Math.round(parsed * 100) : Math.round(parsed);
  }
  const band = (candidate.confidence_band || '').toLowerCase();
  return band === 'high' ? 88 : band === 'medium' ? 64 : 38;
}
function candidateEvidence(candidate: Candidate) {
  const direct = evidenceText(candidate.evidence);
  if (direct) return direct;
  const occurrence = candidate.occurrences?.[0];
  if (occurrence?.method) return `${occurrence.method}${occurrence.offset !== null && occurrence.offset !== undefined ? ` · offset 0x${occurrence.offset.toString(16)}` : ''}`;
  return candidate.source || candidate.method || 'Recovered from a validated evidence stream.';
}
function candidateTransformChain(candidate: Candidate) {
  return candidate.transform_chain || candidate.occurrences?.[0]?.transform_chain || [];
}
function SafePreviewImage({ src, alt }: { src: string; alt: string }) {
  // These URLs are short-lived, locally generated forensic artifacts. Routing
  // them through an image optimizer would duplicate evidence bytes and break
  // the API's strict local-origin boundary.
  // eslint-disable-next-line @next/next/no-img-element
  return <img src={src} alt={alt} loading="lazy" decoding="async" />;
}
function confidenceBand(candidate: Candidate) {
  const score = scoreOf(candidate);
  return score >= 80 ? 'high' : score >= 50 ? 'medium' : 'low';
}
function normalizeUrl(url?: string) {
  if (!url) return '';
  if (/^https?:\/\//i.test(url)) return url;
  return `${API_BASE}${url.startsWith('/') ? '' : '/'}${url}`;
}
const SAFE_PREVIEW_MIME_TYPES = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/bmp']);
const SAFE_AUDIO_MIME_TYPES = new Set(['audio/wav', 'audio/x-wav', 'audio/mpeg', 'audio/ogg', 'audio/flac', 'audio/mp4', 'audio/aac']);
function artifactPreviewUrl(artifact: Artifact) {
  const raw = artifact.preview_url;
  const mediaType = artifactMediaType(artifact).split(';', 1)[0].trim().toLowerCase();
  if (!raw || !SAFE_PREVIEW_MIME_TYPES.has(mediaType)) return '';
  if (/^https?:\/\//i.test(raw)) {
    try {
      if (new URL(raw).origin !== new URL(API_BASE).origin) return '';
    } catch {
      return '';
    }
  }
  return normalizeUrl(raw);
}
function artifactAudioUrl(artifact: Artifact) {
  const raw = artifact.preview_url;
  const mediaType = artifactMediaType(artifact).split(';', 1)[0].trim().toLowerCase();
  if (!raw || !SAFE_AUDIO_MIME_TYPES.has(mediaType)) return '';
  if (/^https?:\/\//i.test(raw)) {
    try {
      if (new URL(raw).origin !== new URL(API_BASE).origin) return '';
    } catch {
      return '';
    }
  }
  return normalizeUrl(raw);
}
function evidenceText(value: unknown) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') return Object.entries(value).map(([key, entry]) => `${key}: ${String(entry)}`).join(' · ');
  return '';
}

function flattenMetadata(value: unknown, limit = 600): MetadataRow[] {
  const rows: MetadataRow[] = [];
  const visit = (current: unknown, path: string, depth: number) => {
    if (rows.length >= limit) return;
    if (current === null || current === undefined || typeof current !== 'object' || depth >= 6) {
      const rendered = typeof current === 'string' ? current : JSON.stringify(current);
      rows.push({ path: path || 'value', value: rendered === undefined ? String(current) : rendered });
      return;
    }
    const entries = Array.isArray(current)
      ? current.map((entry, index) => [String(index), entry] as const)
      : Object.entries(current as Record<string, unknown>);
    if (!entries.length) rows.push({ path: path || 'value', value: Array.isArray(current) ? '[]' : '{}' });
    for (const [key, entry] of entries) visit(entry, path ? `${path}.${key}` : key, depth + 1);
  };
  visit(value, '', 0);
  return rows;
}

function searchable(...values: unknown[]) {
  return values.map((value) => typeof value === 'string' ? value : JSON.stringify(value ?? '')).join(' ').toLowerCase();
}

function boundedDisplay(value: string, maximum = 20_000) {
  return value.length <= maximum ? value : `${value.slice(0, maximum)}\n\n… ${value.length - maximum} more characters are available in the exported report.`;
}

function methodStatusGroup(method: MethodRun): Exclude<MethodFilter, 'all'> {
  const status = (method.status || '').toLowerCase();
  if (['completed', 'success', 'succeeded', 'no_findings'].includes(status)) return 'completed';
  if (status === 'missing') return 'missing';
  if (['skipped', 'not_applicable', 'disabled'].includes(status)) return 'skipped';
  return 'failed';
}

function methodStatusLabel(method: MethodRun) {
  const status = (method.status || 'recorded').toLowerCase();
  if (status === 'no_findings') return 'No findings';
  if (status === 'timed_out') return 'Timed out';
  if (status === 'not_applicable') return 'Not applicable';
  return status.replaceAll('_', ' ');
}

async function readJson<T = unknown>(response: Response): Promise<T> {
  if (response.ok) return await response.json() as T;
  let message = `Request failed (${response.status})`;
  try {
    const data = await response.json() as Record<string, unknown>;
    const detail = data.detail;
    const detailMessage = detail && typeof detail === 'object' ? (detail as Record<string, unknown>).message : undefined;
    const error = data.error;
    const errorMessage = error && typeof error === 'object' ? (error as Record<string, unknown>).message : undefined;
    const candidate = detailMessage || (typeof detail === 'string' ? detail : undefined) || errorMessage || (typeof error === 'string' ? error : undefined) || data.message;
    message = typeof candidate === 'string' ? candidate : message;
  } catch { /* keep the generic safe message */ }
  throw new Error(message);
}

function HomeWorkbench() {
  const fileInput = useRef<HTMLInputElement>(null);
  const [evidenceSection, setEvidenceSection] = useState<EvidenceSection>('image');
  const [screen, setScreen] = useState<Screen>('setup');
  const [profile, setProfile] = useState<Profile>('balanced');
  const [scanOptions, setScanOptions] = useState<ScanOptions>({ ...profileOptionDefaults.balanced, evidence_type: 'image' });
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [flagPrefix, setFlagPrefix] = useState('');
  const [password, setPassword] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [recentJobs, setRecentJobs] = useState<Job[]>([]);
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [toolInstallReport, setToolInstallReport] = useState<ToolInstallReport | null>(null);
  const [toolInstallBusy, setToolInstallBusy] = useState(false);
  const [toolRefreshBusy, setToolRefreshBusy] = useState(false);
  const [engineOnline, setEngineOnline] = useState<boolean | null>(null);
  const [error, setError] = useState('');
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [activeTab, setActiveTab] = useState<ResultTab>('overview');
  const [candidateFilter, setCandidateFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');
  const [methodFilter, setMethodFilter] = useState<MethodFilter>('all');
  const [resultQuery, setResultQuery] = useState('');
  const [selectedVisual, setSelectedVisual] = useState<VisualView | null>(null);
  const [selectedArtifact, setSelectedArtifact] = useState<Artifact | null>(null);
  const [hexArtifactId, setHexArtifactId] = useState('');
  const [hexOffset, setHexOffset] = useState(0);
  const [hexOffsetInput, setHexOffsetInput] = useState('0');
  const [hexSearchInput, setHexSearchInput] = useState('');
  const [hexSearch, setHexSearch] = useState('');
  const [hexSearchMode, setHexSearchMode] = useState<'text' | 'hex'>('text');
  const [hexView, setHexView] = useState<HexView | null>(null);
  const [hexLoading, setHexLoading] = useState(false);
  const [hexError, setHexError] = useState('');
  const hexRequestRef = useRef(0);

  const refreshRecent = useCallback(async () => {
    try {
      const payload = await readJson<unknown>(await fetch(`${API_BASE}/api/jobs`, { cache: 'no-store' }));
      const record = payload && typeof payload === 'object' ? payload as { items?: Job[]; jobs?: Job[] } : {};
      setRecentJobs(Array.isArray(payload) ? payload as Job[] : record.items || record.jobs || []);
    } catch { /* the engine indicator already explains offline state */ }
  }, []);

  const refreshCapabilities = useCallback(async () => {
    const capabilityPayload = await readJson<unknown>(await fetch(`${API_BASE}/api/capabilities?refresh=true`, { cache: 'no-store' }));
    const record = capabilityPayload && typeof capabilityPayload === 'object' ? capabilityPayload as { capabilities?: Capability[]; tools?: Capability[] } : {};
    const next = Array.isArray(capabilityPayload) ? capabilityPayload as Capability[] : record.capabilities || record.tools || [];
    setCapabilities(next);
    return next;
  }, []);

  useEffect(() => {
    let alive = true;
    Promise.all([
      fetch(`${API_BASE}/api/health`, { cache: 'no-store' }).then(readJson),
      fetch(`${API_BASE}/api/capabilities`, { cache: 'no-store' }).then(readJson),
    ]).then(([, capabilityPayload]) => {
      if (!alive) return;
      setEngineOnline(true);
      const record = capabilityPayload && typeof capabilityPayload === 'object' ? capabilityPayload as { capabilities?: Capability[]; tools?: Capability[] } : {};
      setCapabilities(Array.isArray(capabilityPayload) ? capabilityPayload as Capability[] : record.capabilities || record.tools || []);
      refreshRecent();
    }).catch(() => alive && setEngineOnline(false));
    return () => { alive = false; };
  }, [refreshRecent]);

  const refreshJob = useCallback(async (id: string) => {
    if (!id) return;
    try {
      const next = await readJson(await fetch(`${API_BASE}/api/jobs/${id}`, { cache: 'no-store' })) as Job;
      setJob(next);
      if (next.profile) setProfile(next.profile);
      if (next.options) {
        setScanOptions({ ...profileOptionDefaults[next.profile || 'balanced'], ...next.options });
        if (next.options.evidence_type === 'audio' || next.result?.section === 'audio') setEvidenceSection('audio');
        else if (next.options.evidence_type === 'image') setEvidenceSection('image');
      }
      if (TERMINAL.has(next.status.toLowerCase())) {
        setScreen('results');
        refreshRecent();
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not refresh the scan.');
    }
  }, [refreshRecent]);

  const activeJobId = getJobId(job);
  useEffect(() => {
    const id = activeJobId;
    if (!id || screen !== 'running') return;
    let polling: ReturnType<typeof setInterval> | undefined;
    let events: EventSource | undefined;
    const poll = () => refreshJob(id);
    try {
      events = new EventSource(`${API_BASE}/api/jobs/${id}/events`);
      const handleEvent = (event: MessageEvent) => {
        try {
          const envelope = JSON.parse(event.data) as Record<string, unknown>;
          const payload = (envelope.data && typeof envelope.data === 'object' ? envelope.data : envelope) as Record<string, unknown>;
          const detail = payload.detail && typeof payload.detail === 'object' ? payload.detail as Record<string, unknown> : undefined;
          const message = payload.message || detail?.message || payload.stage || payload.status;
          if (message) setActivity((current) => [...current.slice(-19), { at: String(envelope.created_at || new Date().toISOString()), message: String(message), stage: typeof payload.stage === 'string' ? payload.stage : undefined }]);
          if (payload.job && typeof payload.job === 'object') setJob(payload.job as Job);
          else if (payload.status || payload.progress !== undefined || payload.stage) setJob((current) => current ? { ...current, ...payload } : current);
          const eventJob = payload.job && typeof payload.job === 'object' ? payload.job as Record<string, unknown> : undefined;
          if (event.type === 'terminal' || TERMINAL.has(String(payload.status || eventJob?.status || '').toLowerCase())) poll();
        } catch { /* malformed event cannot break polling fallback */ }
      };
      events.onmessage = handleEvent;
      for (const eventType of ['progress', 'warning', 'stage', 'status', 'terminal']) events.addEventListener(eventType, handleEvent);
      events.onerror = () => {
        events?.close();
        if (!polling) polling = setInterval(poll, 1200);
      };
    } catch { polling = setInterval(poll, 1200); }
    polling ||= setInterval(poll, 2500);
    return () => { events?.close(); if (polling) clearInterval(polling); };
  }, [activeJobId, screen, refreshJob]);

  const result = job?.result;
  const isAudioResult = result?.section === 'audio' || job?.options?.evidence_type === 'audio' || evidenceSection === 'audio';
  const candidates = useMemo(() => getCandidates(result).slice().sort((a, b) => scoreOf(b) - scoreOf(a)), [result]);
  const artifacts = useMemo(() => job?.artifacts?.length ? job.artifacts : getArtifacts(result), [job, result]);
  const hexArtifactChoices = useMemo(() => artifacts.filter((artifact) => artifactId(artifact)), [artifacts]);
  const defaultHexArtifactId = artifactId(hexArtifactChoices.find((artifact) => artifact.kind === 'original') || hexArtifactChoices[0] || {});
  const effectiveHexArtifactId = hexArtifactChoices.some((artifact) => artifactId(artifact) === hexArtifactId) ? hexArtifactId : defaultHexArtifactId;
  const loadHexView = useCallback(async (artifactKey: string, offsetValue: number, searchValue: string, mode: 'text' | 'hex') => {
    if (!activeJobId || !artifactKey) return;
    const requestId = ++hexRequestRef.current;
    setHexLoading(true);
    setHexError('');
    const params = new URLSearchParams({ artifact_id: artifactKey, offset: String(Math.max(0, Math.floor(offsetValue))), length: '8192', include_anomalies: 'true' });
    if (searchValue.trim()) {
      params.set('search', searchValue);
      params.set('search_mode', mode);
    }
    try {
      const payload = await readJson<HexView>(await fetch(`${API_BASE}/api/jobs/${activeJobId}/hex?${params.toString()}`, { cache: 'no-store' }));
      if (requestId !== hexRequestRef.current) return;
      setHexView(payload);
      setHexOffset(payload.offset);
      setHexOffsetInput(String(payload.offset));
    } catch (caught) {
      if (requestId !== hexRequestRef.current) return;
      setHexView(null);
      setHexError(caught instanceof Error ? caught.message : 'The hex view could not be loaded.');
    } finally {
      if (requestId === hexRequestRef.current) setHexLoading(false);
    }
  }, [activeJobId]);
  useEffect(() => {
    if (activeTab !== 'hex' || !activeJobId || !effectiveHexArtifactId) return;
    void Promise.resolve().then(() => loadHexView(effectiveHexArtifactId, hexOffset, hexSearch, hexSearchMode));
  }, [activeTab, activeJobId, effectiveHexArtifactId, hexOffset, hexSearch, hexSearchMode, loadHexView]);
  const methods = useMemo(() => getMethods(result), [result]);
  const publicArtifactsByEngineId = useMemo(() => {
    const map = new Map<string, Artifact>();
    for (const artifact of artifacts) {
      const engineId = artifact.metadata?.id;
      if (typeof engineId === 'string') map.set(engineId, artifact);
    }
    return map;
  }, [artifacts]);
  const visuals = useMemo(() => {
    return getVisuals(result).map((view) => {
      const publicArtifact = view.artifact_id ? publicArtifactsByEngineId.get(view.artifact_id) : undefined;
      return publicArtifact ? {
        ...view,
        artifact_id: artifactId(publicArtifact),
        preview_url: publicArtifact.preview_url,
      } : view;
    });
  }, [publicArtifactsByEngineId, result]);
  const toolMethods = useMemo(() => {
    return methods.filter((method) => Boolean(method.tool?.executable || method.command?.length || method.stdout || method.stderr || method.details));
  }, [methods]);
  const declaredExternalToolIds = useMemo(() => new Set(capabilities.map((capability) => capability.id).filter((id): id is string => Boolean(id))), [capabilities]);
  const capabilitiesById = useMemo(() => new Map(capabilities.map((capability) => [capability.id || capability.executable || '', capability])), [capabilities]);
  const findings = useMemo(() => result?.findings || [], [result]);
  const metadataRows = useMemo(() => flattenMetadata(Array.isArray(result?.metadata) ? result?.metadata[0] || {} : result?.metadata || {}), [result]);
  const normalizedQuery = resultQuery.trim().toLowerCase();
  const queryMatches = useCallback((...values: unknown[]) => !normalizedQuery || searchable(...values).includes(normalizedQuery), [normalizedQuery]);
  const filteredCandidates = candidates.filter((candidate) =>
    (candidateFilter === 'all' || confidenceBand(candidate) === candidateFilter)
    && queryMatches(candidateValue(candidate), candidateEvidence(candidate), candidate.reasons, candidate.occurrences, candidateTransformChain(candidate))
  );
  const filteredArtifacts = artifacts.filter((artifact) => queryMatches(artifactName(artifact), artifactMediaType(artifact), artifact.sha256, artifactOrigin(artifact), artifact.metadata));
  const filteredMethods = methods.filter((method) =>
    (methodFilter === 'all' || methodStatusGroup(method) === methodFilter)
    && queryMatches(methodName(method), method.status, method.summary, method.stdout, method.stderr, method.category)
  );
  const filteredToolMethods = toolMethods.filter((method) =>
    (methodFilter === 'all' || methodStatusGroup(method) === methodFilter)
    && queryMatches(methodName(method), method.status, method.summary, method.stdout, method.stderr, method.category, method.command, method.tool?.executable, method.extracted_count)
  );
  const filteredMetadata = metadataRows.filter((row) => queryMatches(row.path, row.value));
  const filteredFindings = findings.filter((finding) => queryMatches(finding.title, finding.description, finding.summary, finding.category, finding.method_id));
  const filteredVisuals = visuals.filter((view) => queryMatches(view.title, view.name, view.kind, view.category));
  const audioKinds = new Set(['audio', 'wav', 'aiff', 'flac', 'ogg', 'mp3', 'aac', 'm4a', 'au', 'asf', 'amr', 'caf', 'midi']);
  const imageKinds = new Set(['png', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'ico']);
  const relevantCapabilities = capabilities.filter((capability) => {
    const formats = capability.formats || ['all'];
    if (formats.includes('all')) return true;
    return formats.some((format) => (evidenceSection === 'audio' ? audioKinds : imageKinds).has(format.toLowerCase()));
  });
  const availableTools = relevantCapabilities.filter((capability) => capability.available === true).length;
  const armedMethodCount = (evidenceSection === 'audio' ? 8 : 10) + availableTools;
  const activeResultTabs = resultTabs.filter((tab) => tab.id !== 'audio' || isAudioResult);
  const audioProperties = result?.audio_analysis?.metadata?.properties || {};
  const audioStatistics = result?.audio_analysis?.metadata?.statistics || {};
  const audioSignals = result?.audio_analysis?.signals || {};
  const audioVisuals = visuals.filter((view) => String(view.category || '').startsWith('audio-'));
  const audioArtifacts = artifacts.filter((artifact) => Boolean(artifactAudioUrl(artifact)));
  const primaryAudioArtifact = audioArtifacts.find((artifact) => artifact.kind === 'original') || audioArtifacts.find((artifact) => artifactName(artifact).includes('audacity_review_normalized')) || audioArtifacts[0];

  function selectFile(file?: File | null) {
    setError('');
    if (!file) return;
    if (file.size > 100 * 1024 * 1024) { setError('That file is larger than the 100 MB safety limit.'); return; }
    setSelectedFile(file);
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    selectFile(event.dataTransfer.files?.[0]);
  }

  async function startScan() {
    if (!selectedFile) { fileInput.current?.click(); return; }
    setError('');
    setActivity([{ at: new Date().toISOString(), message: 'Evidence accepted; creating an immutable working copy.' }]);
    const form = new FormData();
    form.append('file', selectedFile);
    form.append('profile', profile);
    if (flagPrefix.trim()) form.append('flag_prefix', flagPrefix.trim());
    if (password) form.append('password', password);
    form.append('options', JSON.stringify({ ...scanOptions, evidence_type: evidenceSection }));
    try {
      const created = await readJson(await fetch(`${API_BASE}/api/jobs`, { method: 'POST', body: form })) as Job;
      setJob(created);
      setScreen('running');
    } catch (caught) {
      setEngineOnline(false);
      setError(caught instanceof Error ? caught.message : 'The analysis engine could not start this scan.');
    }
  }

  async function cancelScan() {
    const id = getJobId(job);
    if (!id) return;
    try {
      const next = await readJson(await fetch(`${API_BASE}/api/jobs/${id}/cancel`, { method: 'POST' })) as Job;
      setJob(next);
      setActivity((current) => [...current, { at: new Date().toISOString(), message: 'Cancellation requested; preserving partial evidence.' }]);
    } catch (caught) { setError(caught instanceof Error ? caught.message : 'Could not cancel this scan.'); }
  }

  function resetScan() {
    setScreen('setup');
    setSelectedFile(null);
    setJob(null);
    setError('');
    setActivity([]);
    setActiveTab('overview');
    setSelectedVisual(null);
    setSelectedArtifact(null);
    setHexArtifactId('');
    setHexOffset(0);
    setHexOffsetInput('0');
    setHexSearchInput('');
    setHexSearch('');
    setHexView(null);
    setHexError('');
    setResultQuery('');
    setMethodFilter('all');
  }

  function selectEvidenceSection(next: EvidenceSection) {
    setEvidenceSection(next);
    setScreen('setup');
    setSelectedFile(null);
    if (fileInput.current) fileInput.current.value = '';
    setJob(null);
    setError('');
    setActivity([]);
    setActiveTab('overview');
    setSelectedVisual(null);
    setSelectedArtifact(null);
    setHexView(null);
    setHexError('');
    setResultQuery('');
    setToolInstallReport(null);
    setScanOptions({ ...profileOptionDefaults[profile], evidence_type: next });
  }

  function selectHexArtifact(value: string) {
    setHexArtifactId(value);
    setHexOffset(0);
    setHexOffsetInput('0');
    setHexSearchInput('');
    setHexSearch('');
    setHexView(null);
    setHexError('');
  }

  function submitHexSearch(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setHexOffset(0);
    setHexOffsetInput('0');
    setHexSearch(hexSearchInput.trim());
  }

  function goToHexOffset() {
    const value = hexOffsetInput.trim();
    const parsed = /^0x[0-9a-f]+$/i.test(value) ? Number.parseInt(value.slice(2), 16) : Number(value);
    if (!Number.isFinite(parsed) || parsed < 0) {
      setHexError('Enter a valid byte offset, such as 0 or 0x400.');
      return;
    }
    setHexError('');
    setHexOffset(Math.floor(parsed));
  }

  function jumpToHexOffset(value: number) {
    const next = Math.max(0, Math.floor(value));
    setHexError('');
    setHexOffset(next);
    setHexOffsetInput(String(next));
  }

  function chooseProfile(next: Profile) {
    setProfile(next);
    const defaults = profileOptionDefaults[next];
    setScanOptions((current) => ({
      ...current,
      max_recursion_depth: defaults.max_recursion_depth,
      max_artifacts: defaults.max_artifacts,
      tool_timeout_seconds: defaults.tool_timeout_seconds,
      foremost_depth: defaults.foremost_depth,
      audio_analysis_seconds: defaults.audio_analysis_seconds,
      audio_spectrogram_fft: defaults.audio_spectrogram_fft,
      audio_lsb_bits: defaults.audio_lsb_bits,
    }));
  }

  function toggleExternalTool(toolId: string, enabled: boolean) {
    const declared = capabilities.map((item) => item.id).filter((item): item is string => Boolean(item));
    setScanOptions((current) => {
      const selected = new Set(current.selected_external_tools ?? declared);
      if (enabled) selected.add(toolId); else selected.delete(toolId);
      return { ...current, selected_external_tools: [...selected] };
    });
  }

  async function installMissingTools(requested?: string[]) {
    const missing = requested || relevantCapabilities.filter((capability) => capability.available !== true).map((capability) => capability.id || capability.executable).filter((id): id is string => Boolean(id));
    if (!missing.length) {
      setToolInstallReport({ status: 'completed', installed_count: 0, message: 'All declared tools are already available.' });
      return;
    }
    if (!window.confirm(`Install ${missing.length} missing forensic tool${missing.length === 1 ? '' : 's'} automatically? The local API will use fixed packages from Kali WSL and Windows Package Manager. This can take several minutes.`)) return;
    setToolInstallBusy(true);
    setToolInstallReport(null);
    try {
      const response = await fetch(`${API_BASE}/api/tools/install`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool_ids: missing, confirmed: true }),
      });
      const report = await readJson<ToolInstallReport>(response);
      setToolInstallReport(report);
      try { await refreshCapabilities(); } catch { /* keep the install report when refresh is unavailable */ }
    } catch (caught) {
      setToolInstallReport({ status: 'failed', message: caught instanceof Error ? caught.message : 'Automatic tool installation could not be started.' });
    } finally {
      setToolInstallBusy(false);
    }
  }

  async function refreshToolAvailability() {
    setToolRefreshBusy(true);
    try {
      await refreshCapabilities();
      setEngineOnline(true);
      setError('');
    } catch (caught) {
      setEngineOnline(false);
      setError(caught instanceof Error ? caught.message : 'Could not refresh tool availability.');
    } finally {
      setToolRefreshBusy(false);
    }
  }

  async function openRecent(recent: Job) {
    setJob(recent);
    setActiveTab('overview');
    if (recent.profile) setProfile(recent.profile);
    if (recent.options) setScanOptions({ ...profileOptionDefaults[recent.profile || 'balanced'], ...recent.options });
    setEvidenceSection(recent.options?.evidence_type === 'audio' || recent.result?.section === 'audio' ? 'audio' : 'image');
    const id = getJobId(recent);
    if (id) await refreshJob(id);
    setScreen(TERMINAL.has(recent.status.toLowerCase()) ? 'results' : 'running');
  }

  const jobId = activeJobId;
  const rawProgress = Number(job?.progress || 0);
  const progress = Math.max(0, Math.min(100, rawProgress > 0 && rawProgress <= 1 ? rawProgress * 100 : rawProgress));
  const currentStage = job?.current_stage || job?.stage || job?.message || 'Preparing analyzers';
  const successfulMethods = methods.filter((method) => ['completed', 'success', 'succeeded', 'no_findings'].includes((method.status || '').toLowerCase())).length;

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <button className="brand brand-button" onClick={resetScan} aria-label="Return to new scan">
          <span className="brand-mark" aria-hidden="true">F</span>
          <span><strong>Forenscope</strong><small>CTF workbench</small></span>
        </button>

        <nav aria-label="Forensics sections">
          <p className="nav-label">Analyze</p>
          <button className={`nav-item ${evidenceSection === 'image' ? 'active' : ''}`} onClick={() => selectEvidenceSection('image')}><span>◫</span>Image</button>
          <button className={`nav-item ${evidenceSection === 'audio' ? 'active' : ''}`} onClick={() => selectEvidenceSection('audio')}><span>≋</span>Audio<em>Ready</em></button>
          <button className="nav-item disabled" disabled><span>⌁</span>Corrupted files<em>Soon</em></button>
          <p className="nav-label second">Workspace</p>
          <button className="nav-item" onClick={() => document.getElementById('recent-scans')?.scrollIntoView({ behavior: 'smooth' })}><span>◷</span>Recent scans</button>
          <button className="nav-item" onClick={() => setShowAdvanced(true)}><span>⌘</span>Scan settings</button>
        </nav>

        <div className="recent-mini" id="recent-scans">
          {recentJobs.slice(0, 3).map((recent) => (
            <button key={getJobId(recent)} onClick={() => openRecent(recent)}>
              <span className={`mini-status ${recent.status}`} />
              <span><strong>{jobName(recent) || `${recent.options?.evidence_type === 'audio' ? 'Audio' : 'Image'} scan`}</strong><small>{recent.status}</small></span>
            </button>
          ))}
        </div>

        <div className={`privacy-card ${engineOnline === false ? 'offline' : ''}`}>
          <span className="status-dot" />
          <div>
            <strong>{engineOnline === false ? 'Engine offline' : 'Local & offline'}</strong>
            <p>{engineOnline === false ? 'Start the local API to analyze.' : 'Evidence stays on this device.'}</p>
          </div>
        </div>
      </aside>

      <section className={`workspace screen-${screen}`}>
        {screen === 'setup' && (
          <>
            <header className="topbar">
              <div><p className="eyebrow">{evidenceSection === 'audio' ? 'Audio forensics' : 'Image forensics'}</p><h1>{evidenceSection === 'audio' ? 'Hear what the waveform is hiding.' : 'Find what the pixels are hiding.'}</h1></div>
              <div className="top-actions">
                <button className="icon-button" aria-label="Open method settings" onClick={() => setShowAdvanced(true)}>⚙</button>
                <button className="new-scan" onClick={() => fileInput.current?.click()}>New scan <span>＋</span></button>
              </div>
            </header>

            <div className="content-grid">
              <section className="primary-column">
                <div
                  className={`upload-card ${dragging ? 'dragging' : ''} ${selectedFile ? 'has-file' : ''}`}
                  onDragEnter={(event) => { event.preventDefault(); setDragging(true); }}
                  onDragOver={(event) => event.preventDefault()}
                  onDragLeave={() => setDragging(false)}
                  onDrop={handleDrop}
                  onClick={() => !selectedFile && fileInput.current?.click()}
                >
                  <input ref={fileInput} className="sr-only" type="file" accept={evidenceSection === 'audio' ? '.wav,.wave,.mp3,.flac,.ogg,.oga,.opus,.m4a,.aac,.aif,.aiff,.aifc,.au,.snd,.wma,.amr,.caf,.mid,.midi,audio/*,application/octet-stream' : '.png,.apng,.jpg,.jpeg,.gif,.bmp,.webp,.tif,.tiff,.ico,application/octet-stream'} onChange={(event) => selectFile(event.target.files?.[0])} />
                  {!selectedFile ? (
                    <>
                      <div className="upload-icon" aria-hidden="true"><span>↑</span></div>
                      <p className="card-kicker">Start an investigation</p>
                      <h2>{evidenceSection === 'audio' ? 'Drop an audio file here' : 'Drop an image here'}</h2>
                      <p className="upload-copy">{evidenceSection === 'audio' ? 'WAV, MP3, FLAC, Ogg/Opus, M4A, AIFF, AU, WMA, AMR, CAF or MIDI' : 'PNG, JPEG, GIF, BMP, WebP, TIFF or ICO'} · up to 100 MB</p>
                      <button className="choose-button" onClick={(event) => { event.stopPropagation(); fileInput.current?.click(); }}>Choose evidence file</button>
                      <p className="evidence-note"><span>◇</span>The original is hashed and never modified</p>
                    </>
                  ) : (
                    <>
                      <div className="file-seal" aria-hidden="true"><span>{evidenceSection === 'audio' ? '≋' : '◫'}</span><i>Evidence</i></div>
                      <p className="card-kicker">Evidence selected</p>
                      <h2 className="file-name">{selectedFile.name}</h2>
                      <div className="file-facts"><span>{formatBytes(selectedFile.size)}</span><span>SHA-256 on ingest</span><span>Type verified by content</span></div>
                      <div className="file-actions">
                        <button className="choose-button" onClick={(event) => { event.stopPropagation(); startScan(); }}>Analyze {evidenceSection} <span>→</span></button>
                        <button className="replace-button" onClick={(event) => { event.stopPropagation(); fileInput.current?.click(); }}>Replace</button>
                      </div>
                      <p className="evidence-note"><span>◇</span>{evidenceSection === 'audio' ? 'Playback uses only content-verified local audio' : 'Preview waits for the sandboxed safe renderer'}</p>
                    </>
                  )}
                </div>

                {error && <div className="error-banner" role="alert"><span>!</span><p>{error}</p><button onClick={() => setError('')} aria-label="Dismiss error">×</button></div>}

                <div className="section-heading">
                  <div><p className="eyebrow">Analysis depth</p><h2>Choose a scan profile</h2></div>
                  <button className="text-button" onClick={() => setShowAdvanced(true)}>Customize methods →</button>
                </div>
                <div className="profile-grid">
                  {profiles.map((item) => (
                    <button key={item.id} className={`profile-card ${profile === item.id ? 'selected' : ''}`} onClick={() => chooseProfile(item.id)} aria-pressed={profile === item.id}>
                      <span className="profile-symbol">{item.symbol}</span>
                      <span><strong>{item.name}</strong><small>{item.copy}</small></span>
                      <em>{item.tag}</em>
                    </button>
                  ))}
                </div>
                <div className="flag-pattern mobile-analysis-options">
                  <label htmlFor="flag-prefix-mobile">Flag prefix <span>Optional</span></label>
                  <div className="input-shell"><input id="flag-prefix-mobile" value={flagPrefix} onChange={(event) => setFlagPrefix(event.target.value.slice(0, 64))} placeholder="e.g. picoCTF, HTB, flag" /><kbd>{'{…}'}</kbd></div>
                  <p>Specific prefixes rank true flags above decoys.</p>
                  <button className="password-toggle" onClick={() => setShowPassword((open) => !open)}>{showPassword ? 'Hide passphrase / key' : '+ Add a passphrase or key'}</button>
                  {showPassword && <><input className="password-input" type="password" value={password} autoComplete="off" onChange={(event) => setPassword(event.target.value.slice(0, 256))} placeholder="Optional stego or decryption passphrase" /><small className="password-hint">Used only for this scan. {evidenceSection === 'audio' ? 'Steghide can inspect WAV/AU payloads; extracted PCM bits and carved data also enter bounded encrypted-payload recovery.' : 'Steghide, Stegseek and OutGuess use it for bounded extraction; encrypted payload checks support OpenSSL salted AES and passphrase-based XOR.'} Prefix a raw key with <code>hex:</code>.</small></>}
                </div>
                {recentJobs.length > 0 && (
                  <section className="mobile-recent-scans" aria-labelledby="mobile-recent-title">
                    <div><p className="eyebrow">Workspace</p><h2 id="mobile-recent-title">Recent investigations</h2></div>
                    <div>
                      {recentJobs.slice(0, 5).map((recent) => (
                        <button key={getJobId(recent)} onClick={() => openRecent(recent)}>
                          <span className={`mini-status ${recent.status}`} />
                          <span><strong>{jobName(recent) || `${recent.options?.evidence_type === 'audio' ? 'Audio' : 'Image'} scan`}</strong><small>{formatDate(recent.updated_at)}</small></span>
                          <em>{recent.status}</em>
                        </button>
                      ))}
                    </div>
                  </section>
                )}
              </section>

              <aside className="inspector-column">
                <div className="panel-heading">
                  <div><p className="eyebrow">Coverage</p><h2>{armedMethodCount} methods armed</h2></div>
                  <span className="shield-badge">✓ Safe mode</span>
                </div>
                <div className="methods-list">
                  {(evidenceSection === 'audio' ? audioMethodGroups : methodGroups).map((method, index) => (
                    <div className="method-row" key={method.title}>
                      <span className={`method-number tone-${method.tone}`}>{String(index + 1).padStart(2, '0')}</span>
                      <span className="method-copy"><strong>{method.title}</strong><small>{method.copy}</small></span>
                      <span className="method-state">Ready</span>
                    </div>
                  ))}
                </div>
                <div className="flag-pattern">
                  <label htmlFor="flag-prefix">Flag prefix <span>Optional</span></label>
                  <div className="input-shell"><input id="flag-prefix" value={flagPrefix} onChange={(event) => setFlagPrefix(event.target.value.slice(0, 64))} placeholder="e.g. picoCTF, HTB, flag" /><kbd>{'{…}'}</kbd></div>
                  <p>Specific prefixes rank true flags above decoys.</p>
                  <button className="password-toggle" onClick={() => setShowPassword((open) => !open)}>{showPassword ? 'Hide passphrase / key' : '+ Add a passphrase or key'}</button>
                  {showPassword && <><input className="password-input" type="password" value={password} autoComplete="off" onChange={(event) => setPassword(event.target.value.slice(0, 256))} placeholder="Optional stego or decryption passphrase" /><small className="password-hint">Used only for this scan. {evidenceSection === 'audio' ? 'Steghide can inspect WAV/AU payloads; extracted PCM bits and carved data also enter bounded encrypted-payload recovery.' : 'Steghide, Stegseek and OutGuess use it for bounded extraction; encrypted payload checks support OpenSSL salted AES and passphrase-based XOR.'} Prefix a raw key with <code>hex:</code>.</small></>}
                </div>
                <div className={`engine-status ${engineOnline === false ? 'engine-offline' : ''}`}>
                  <span className="pulse-ring"><i /></span>
                  <span><strong>{engineOnline === false ? 'Analysis engine is offline' : 'Analysis engine ready'}</strong><small>{engineOnline === false ? 'The interface remains available' : `Offline · isolated · ${recentJobs.filter((item) => !TERMINAL.has(item.status.toLowerCase())).length} active jobs`}</small></span>
                </div>
              </aside>
            </div>
          </>
        )}

        {screen === 'running' && (
          <>
            <header className="topbar running-topbar">
              <div><p className="eyebrow">Live investigation</p><h1>Interrogating <span>{jobName(job) || selectedFile?.name || 'evidence'}</span></h1></div>
              <button className="cancel-button" onClick={cancelScan} disabled={job?.status.toLowerCase() === 'cancelling'}>Stop scan</button>
            </header>
            {error && <div className="error-banner wide" role="alert"><span>!</span><p>{error}</p><button onClick={() => setError('')}>×</button></div>}
            <div className="running-grid">
              <section className="scan-stage-card">
                <div className="radar-wrap">
                  <div className={`progress-ring ${progress ? '' : 'indeterminate'}`} style={{ '--progress': `${progress}%` } as CSSProperties}>
                    <div><strong>{progress ? `${Math.round(progress)}%` : '•••'}</strong><small>{job?.status || 'Running'}</small></div>
                  </div>
                  <span className="radar-orbit orbit-one" /><span className="radar-orbit orbit-two" />
                </div>
                <p className="card-kicker">Current method</p>
                <h2>{currentStage}</h2>
                <p className="stage-copy">Every parser runs against an isolated per-job working copy. Results appear as soon as they are validated.</p>
                <div className="live-progress"><span style={{ width: progress ? `${progress}%` : '34%' }} /></div>
                <div className="live-stats">
                  <div><strong>{successfulMethods}</strong><span>Methods complete</span></div>
                  <div><strong>{artifacts.length}</strong><span>Artifacts</span></div>
                  <div><strong>{candidates.length}</strong><span>Candidates</span></div>
                </div>
              </section>

              <aside className="activity-panel">
                <div className="activity-heading"><div><p className="eyebrow">Evidence trail</p><h2>Live activity</h2></div><span className="live-chip"><i /> Live</span></div>
                <div className="activity-list" aria-live="polite">
                  {activity.length ? activity.slice().reverse().map((item, index) => (
                    <div className={`activity-item ${index === 0 ? 'current' : ''}`} key={`${item.at}-${index}`}>
                      <span>{index === 0 ? '◉' : '✓'}</span>
                      <div><strong>{item.message}</strong><small>{new Date(item.at).toLocaleTimeString()}</small></div>
                    </div>
                  )) : <p className="empty-copy">Waiting for the first analyzer event…</p>}
                </div>
                <div className="sandbox-note"><span>⌾</span><div><strong>Safety limits active</strong><p>No network calls · bounded outputs · immutable source</p></div></div>
              </aside>
            </div>
          </>
        )}

        {screen === 'results' && (
          <>
            <header className="results-header">
              <div className="result-title-row">
                <button className="back-button" onClick={resetScan} aria-label="Start another scan">←</button>
                <div><p className="eyebrow">{isAudioResult ? 'Audio investigation complete' : 'Investigation complete'}</p><h1>{jobName(job) || selectedFile?.name || `${isAudioResult ? 'Audio' : 'Image'} analysis`}</h1></div>
              </div>
              <div className="result-actions">
                <a className="report-button secondary" href={`${API_BASE}/api/jobs/${jobId}/report.json`} download>JSON</a>
                <a className="report-button secondary" href={`${API_BASE}/api/jobs/${jobId}/report.html`} download>HTML</a>
                <a className="report-button" href={`${API_BASE}/api/jobs/${jobId}/report.zip`} download>Export case <span>↓</span></a>
              </div>
            </header>

            <section className="case-strip">
              <div><span>Status</span><strong className={`case-status ${job?.status}`}>{job?.status || 'complete'}</strong></div>
              <div><span>Profile</span><strong>{job?.profile || profile}</strong></div>
              <div><span>Evidence hash</span><strong className="mono">{String(job?.sha256 || job?.input_sha256 || result?.input?.sha256 || 'pending').slice(0, 16)}…</strong></div>
              <div><span>Completed</span><strong>{formatDate(job?.updated_at)}</strong></div>
              <button onClick={resetScan}>New investigation ＋</button>
            </section>

            {candidates.length > 0 ? (
              <section className="hero-finding">
                <div className="finding-mark"><span>✦</span></div>
                <div className="finding-copy">
                  <div className="finding-label"><span>Strongest candidate</span><em className={confidenceBand(candidates[0])}>{scoreOf(candidates[0])}% confidence</em></div>
                  <code>{candidateValue(candidates[0])}</code>
                  <p>{candidateEvidence(candidates[0])}</p>
                </div>
                <button onClick={() => navigator.clipboard?.writeText(candidateValue(candidates[0]))}>Copy flag</button>
              </section>
            ) : (
              <section className="no-candidate-hero"><span>◇</span><div><strong>No high-confidence flag was found</strong><p>{isAudioResult ? 'Review the spectrogram, PCM bit streams, channel difference, SSTV signals and complete tool output below.' : 'The completed coverage remains available below. Try Deep mode, a challenge prefix, or a known passphrase.'}</p></div></section>
            )}

            <nav className="result-tabs" aria-label="Analysis result sections">
              {activeResultTabs.map((tab) => <button key={tab.id} className={activeTab === tab.id ? 'active' : ''} onClick={() => setActiveTab(tab.id)}>{tab.label}{tab.id === 'audio' && <span>{audioVisuals.length}</span>}{tab.id === 'candidates' && <span>{candidates.length}</span>}{tab.id === 'artifacts' && <span>{artifacts.length}</span>}{tab.id === 'metadata' && <span>{metadataRows.length}</span>}{tab.id === 'tools' && <span>{toolMethods.length}</span>}{tab.id === 'methods' && <span>{methods.length}</span>}</button>)}
            </nav>

            <div className="result-search">
              <span aria-hidden="true">⌕</span>
              <label className="sr-only" htmlFor="evidence-search">Search all recovered information</label>
              <input id="evidence-search" type="search" value={resultQuery} onChange={(event) => setResultQuery(event.target.value)} placeholder="Search flags, metadata, hashes, artifacts and tool output…" />
              {resultQuery && <button onClick={() => setResultQuery('')} aria-label="Clear evidence search">Clear</button>}
              <small>{resultQuery ? `${filteredCandidates.length + filteredArtifacts.length + filteredToolMethods.length + filteredMetadata.length} matching records` : `${candidates.length + artifacts.length + toolMethods.length + metadataRows.length} indexed records`}</small>
            </div>

            <div className="result-content">
              {activeTab === 'overview' && (
                <div className="overview-grid">
                  <section className="metric-grid">
                    <div className="metric-card green"><span>✦</span><strong>{candidates.length}</strong><p>Flag candidates</p><small>{candidates.filter((item) => confidenceBand(item) === 'high').length} high confidence</small></div>
                    <div className="metric-card blue"><span>⌁</span><strong>{artifacts.length}</strong><p>Recovered artifacts</p><small>All lineage preserved</small></div>
                    <div className="metric-card purple"><span>⌘</span><strong>{successfulMethods || methods.length}</strong><p>Methods completed</p><small>{methods.filter((item) => ['failed', 'timeout', 'tool_error'].includes((item.status || '').toLowerCase())).length} limited or failed</small></div>
                    <div className="metric-card amber"><span>◫</span><strong>{visuals.length}</strong><p>Visual derivatives</p><small>Safe PNG previews</small></div>
                  </section>
                  <section className="findings-panel">
                    <div className="section-title"><div><p className="eyebrow">Notable evidence</p><h2>What deserves attention</h2></div><span>{findings.length} findings</span></div>
                    <div className="finding-list">
                      {filteredFindings.slice(0, 8).map((finding, index) => (
                        <article key={finding.id || `${finding.title}-${index}`}>
                          <span className="finding-index">{String(index + 1).padStart(2, '0')}</span>
                          <div><strong>{finding.title || finding.category || 'Forensic finding'}</strong><p>{finding.description || finding.summary || finding.evidence || 'Evidence recorded by the analysis engine.'}</p><small>{finding.method_id || finding.method || finding.category}{finding.offset !== undefined ? ` · offset 0x${finding.offset.toString(16)}` : ''}</small></div>
                        </article>
                      ))}
                      {!filteredFindings.length && <div className="empty-state"><span>✓</span><strong>{resultQuery ? 'No findings match this search' : 'No structural warnings were reported'}</strong><p>Review method coverage for skipped or unavailable tools.</p></div>}
                    </div>
                  </section>
                </div>
              )}

              {activeTab === 'audio' && isAudioResult && (
                <section className="tab-panel audio-lab-panel">
                  <div className="section-title"><div><p className="eyebrow">Signal workstation</p><h2>Audio laboratory</h2></div><span>{audioVisuals.length} visual analyses · {audioArtifacts.length} playable files</span></div>
                  <p className="panel-lede">Listen to content-verified local audio, compare waveform and spectral evidence, inspect decoded tones, and download channel or Audacity review exports without changing the source.</p>
                  <div className="audio-player-card">
                    <div><span className="audio-player-mark">≋</span><div><strong>{primaryAudioArtifact ? artifactName(primaryAudioArtifact) : 'No browser-playable artifact'}</strong><small>{primaryAudioArtifact ? `${artifactMediaType(primaryAudioArtifact)} · ${formatBytes(artifactSize(primaryAudioArtifact))}` : 'Install FFmpeg to create a PCM review WAV for this format.'}</small></div></div>
                    {primaryAudioArtifact && artifactAudioUrl(primaryAudioArtifact) ? <audio controls preload="metadata" src={artifactAudioUrl(primaryAudioArtifact)}>Your browser cannot play this verified audio artifact.</audio> : <p>Playback is unavailable, but waveform, metadata, carving, and raw-tool evidence remain accessible.</p>}
                  </div>
                  <div className="audio-stat-grid">
                    <div><strong>{audioProperties.duration_seconds !== undefined ? `${Number(audioProperties.duration_seconds).toFixed(3)} s` : '—'}</strong><small>duration</small></div>
                    <div><strong>{audioProperties.sample_rate !== undefined ? `${Number(audioProperties.sample_rate).toLocaleString()} Hz` : '—'}</strong><small>sample rate</small></div>
                    <div><strong>{audioProperties.channels !== undefined ? String(audioProperties.channels) : '—'}</strong><small>channels</small></div>
                    <div><strong>{audioProperties.bit_depth !== undefined ? `${String(audioProperties.bit_depth)} bit` : '—'}</strong><small>PCM depth</small></div>
                    <div><strong>{audioStatistics.rms_dbfs !== undefined ? `${Number(audioStatistics.rms_dbfs).toFixed(2)} dBFS` : '—'}</strong><small>RMS level</small></div>
                    <div><strong>{audioStatistics.stereo_correlation !== undefined && audioStatistics.stereo_correlation !== null ? Number(audioStatistics.stereo_correlation).toFixed(4) : '—'}</strong><small>stereo correlation</small></div>
                  </div>
                  <div className="audio-lab-grid">
                    <section className="audio-visual-section">
                      <div className="audio-subheading"><div><p className="eyebrow">Visual evidence</p><h3>Waveform &amp; spectrum</h3></div><span>{audioVisuals.length}</span></div>
                      <div className="audio-visual-grid">
                        {audioVisuals.map((view, index) => {
                          const preview = normalizeUrl(view.preview_url) || (view.artifact_id ? `${API_BASE}/api/jobs/${jobId}/artifacts/${view.artifact_id}/preview` : '');
                          return <button key={view.id || index} onClick={() => { setSelectedVisual({ ...view, preview_url: preview }); setActiveTab('visual'); }}><SafePreviewImage src={preview} alt={view.title || `Audio visual ${index + 1}`} /><span><strong>{view.title || `Audio visual ${index + 1}`}</strong><small>{view.category || 'signal visualization'} · open full view</small></span></button>;
                        })}
                        {!audioVisuals.length && <div className="empty-state large"><span>≋</span><strong>No spectral image is available</strong><p>For compressed audio, install FFmpeg or SoX and scan again.</p></div>}
                      </div>
                    </section>
                    <aside className="audio-signal-panel">
                      <div className="audio-subheading"><div><p className="eyebrow">Decoded signals</p><h3>Automatic detections</h3></div></div>
                      <div className="audio-signal-cards">
                        <article><span>DTMF</span><strong>{audioSignals.dtmf?.symbols || 'None'}</strong><small>{audioSignals.dtmf?.events?.length || 0} bounded event(s)</small></article>
                        <article><span>Morse</span><strong>{audioSignals.morse?.text || 'None'}</strong><small>{audioSignals.morse?.pattern ? String(audioSignals.morse.pattern).slice(0, 70) : 'No confident keying sequence'}</small></article>
                        <article className={audioSignals.sstv?.candidate ? 'warning' : ''}><span>SSTV</span><strong>{audioSignals.sstv?.candidate ? 'Possible transmission' : 'No preamble'}</strong><small>{audioSignals.sstv?.leader_frames || 0} leader · {audioSignals.sstv?.sync_frames || 0} sync frames</small></article>
                        <article><span>Ultrasonic</span><strong>{audioSignals.ultrasonic_energy_ratio !== undefined ? `${(Number(audioSignals.ultrasonic_energy_ratio) * 100).toFixed(3)}%` : '—'}</strong><small>energy above 18 kHz</small></article>
                      </div>
                      <div className="audio-frequency-list"><span>Strong frequency peaks</span>{audioSignals.frequency_peaks?.slice(0, 8).map((peak, index) => <div key={`${peak.frequency_hz}-${index}`}><strong>{Number(peak.frequency_hz || 0).toFixed(2)} Hz</strong><small>{Number(peak.relative_db || 0).toFixed(2)} dB relative</small></div>)}{!audioSignals.frequency_peaks?.length && <p>No decoded PCM spectrum is available.</p>}</div>
                    </aside>
                  </div>
                  <section className="audio-export-section">
                    <div className="audio-subheading"><div><p className="eyebrow">Audacity-compatible evidence</p><h3>Review exports</h3></div><span>Immutable derivatives</span></div>
                    <div className="audio-export-grid">
                      {artifacts.filter((artifact) => /audacity|audio_(?:mono|left|right|stereo)/i.test(artifactName(artifact))).map((artifact) => <a key={artifactId(artifact)} href={normalizeUrl(artifact.download_url) || `${API_BASE}/api/jobs/${jobId}/artifacts/${artifactId(artifact)}/download`} download><span>{artifactMediaType(artifact).startsWith('audio/') ? '≋' : '⌁'}</span><div><strong>{artifactName(artifact)}</strong><small>{formatBytes(artifactSize(artifact))} · import into Audacity</small></div><em>↓</em></a>)}
                      {!artifacts.some((artifact) => /audacity|audio_(?:mono|left|right|stereo)/i.test(artifactName(artifact))) && <div className="empty-state"><span>⌁</span><strong>No review bundle was generated</strong><p>Enable Audacity handoff or channel isolation before the next scan.</p></div>}
                    </div>
                  </section>
                </section>
              )}

              {activeTab === 'candidates' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">Ranked evidence</p><h2>Flag candidates</h2></div><div className="filter-pills">{(['all', 'high', 'medium', 'low'] as const).map((filter) => <button key={filter} className={candidateFilter === filter ? 'active' : ''} onClick={() => setCandidateFilter(filter)}>{filter}</button>)}</div></div>
                  <div className="candidate-list">
                    {filteredCandidates.map((candidate, index) => (
                      <article className="candidate-card" key={candidate.id || `${candidateValue(candidate)}-${index}`}>
                        <div className={`score-orb ${confidenceBand(candidate)}`}><strong>{scoreOf(candidate)}</strong><small>%</small></div>
                        <div className="candidate-main"><div><span className={`confidence-chip ${confidenceBand(candidate)}`}>{confidenceBand(candidate)} confidence</span><small>Candidate {String(index + 1).padStart(2, '0')}</small></div><code>{candidateValue(candidate)}</code><p>{candidateEvidence(candidate)}</p>{candidateTransformChain(candidate).length ? <div className="transform-chain">{candidateTransformChain(candidate).map((step) => <span key={step}>{step}</span>)}</div> : null}{(candidate.reasons?.length || candidate.occurrences?.length) ? <details className="evidence-trace"><summary>Show evidence trace</summary>{candidate.reasons?.map((reason) => <p key={reason}>✓ {reason}</p>)}{candidate.occurrences?.map((occurrence, occurrenceIndex) => <p key={`${occurrence.method}-${occurrence.offset}-${occurrenceIndex}`}><strong>{occurrence.method || 'analyzer'}</strong>{occurrence.offset !== null && occurrence.offset !== undefined ? ` · offset 0x${occurrence.offset.toString(16)}` : ''}{occurrence.artifact_id ? ` · ${occurrence.artifact_id}` : ''}</p>)}</details> : null}</div>
                        <button onClick={() => navigator.clipboard?.writeText(candidateValue(candidate))}>Copy</button>
                      </article>
                    ))}
                    {!filteredCandidates.length && <div className="empty-state large"><span>◇</span><strong>No candidates in this confidence band</strong><p>All raw evidence remains available in the artifact and method views.</p></div>}
                  </div>
                </section>
              )}

              {activeTab === 'artifacts' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">Extraction lineage</p><h2>Recovered artifact tree</h2></div><span>{formatBytes(artifacts.reduce((sum, item) => sum + artifactSize(item), 0))} total</span></div>
                  <div className="artifact-workspace">
                    <div className="artifact-table" role="table" aria-label="Recovered artifacts">
                      <div className="artifact-head" role="row"><span>Name</span><span>Type</span><span>Size</span><span>SHA-256</span><span /></div>
                      {filteredArtifacts.map((artifact, index) => {
                        const id = artifactId(artifact);
                        const download = normalizeUrl(artifact.download_url) || `${API_BASE}/api/jobs/${jobId}/artifacts/${id}?download=1`;
                        return <div className={`artifact-row ${artifactId(selectedArtifact || {}) === id ? 'selected' : ''}`} role="row" key={id || index} style={{ '--depth': Math.min(artifactDepth(artifact), 4) } as CSSProperties}><span><i>{artifact.parent_id || artifactDepth(artifact) ? '└' : '◆'}</i><button className="artifact-open" onClick={() => setSelectedArtifact(artifact)}><strong>{artifactName(artifact)}</strong><small>{artifactOrigin(artifact)}</small></button></span><span><em>{artifactMediaType(artifact)}</em></span><span>{formatBytes(artifactSize(artifact))}</span><span className="mono">{artifact.sha256?.slice(0, 12) || '—'}</span><a href={download} download aria-label={`Download ${artifactName(artifact)}`}>↓</a></div>;
                      })}
                      {!filteredArtifacts.length && <div className="empty-state large"><span>⌁</span><strong>{resultQuery ? 'No artifacts match this search' : 'No child artifacts were recovered'}</strong><p>The original evidence and method logs are still included in the report.</p></div>}
                    </div>
                    {selectedArtifact && <aside className="artifact-inspector"><header><div><p className="eyebrow">Evidence inspector</p><h3>{artifactName(selectedArtifact)}</h3></div><button onClick={() => setSelectedArtifact(null)} aria-label="Close artifact inspector">×</button></header>{artifactPreviewUrl(selectedArtifact) ? <div className="artifact-preview"><SafePreviewImage src={artifactPreviewUrl(selectedArtifact)} alt={`Preview of ${artifactName(selectedArtifact)}`} /><small>Verified raster preview · served read-only</small></div> : artifactAudioUrl(selectedArtifact) ? <div className="artifact-audio-preview"><audio controls preload="metadata" src={artifactAudioUrl(selectedArtifact)} /><small>Content-verified local audio · served read-only</small></div> : null}<dl><div><dt>Type</dt><dd>{artifactMediaType(selectedArtifact)}</dd></div><div><dt>Size</dt><dd>{formatBytes(artifactSize(selectedArtifact))}</dd></div><div><dt>Origin</dt><dd>{artifactOrigin(selectedArtifact)}</dd></div><div><dt>Depth</dt><dd>{artifactDepth(selectedArtifact)}</dd></div><div className="full"><dt>SHA-256</dt><dd className="mono">{selectedArtifact.sha256 || 'Unavailable'}</dd></div>{selectedArtifact.parent_id && <div className="full"><dt>Parent</dt><dd className="mono">{selectedArtifact.parent_id}</dd></div>}</dl><details className="raw-details"><summary>Lineage &amp; metadata</summary><pre>{JSON.stringify(selectedArtifact.metadata || {}, null, 2)}</pre></details><a className="inspector-download" href={normalizeUrl(selectedArtifact.download_url) || `${API_BASE}/api/jobs/${jobId}/artifacts/${artifactId(selectedArtifact)}?download=1`} download>Download evidence ↓</a></aside>}
                  </div>
                </section>
              )}

              {activeTab === 'visual' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">{isAudioResult ? 'Signal visualization' : 'Pixel laboratory'}</p><h2>{isAudioResult ? 'Waveforms & spectrograms' : 'Channels, bit planes & frames'}</h2></div><span>{visuals.length} safe previews</span></div>
                  <div className="visual-layout">
                    <div className="visual-grid">
                      {filteredVisuals.map((view, index) => {
                        const preview = normalizeUrl(view.preview_url) || (view.artifact_id ? `${API_BASE}/api/jobs/${jobId}/artifacts/${view.artifact_id}/preview` : '');
                        return <button key={view.id || `${view.name}-${index}`} onClick={() => setSelectedVisual({ ...view, preview_url: preview })} className={selectedVisual?.id === view.id ? 'active' : ''}>{preview ? <SafePreviewImage src={preview} alt={view.title || view.name || `Visual derivative ${index + 1}`} /> : <span className="visual-placeholder">◫</span>}<span><strong>{view.title || view.name || `View ${index + 1}`}</strong><small>{view.kind || 'Derived image'}</small></span></button>;
                      })}
                      {!filteredVisuals.length && <div className="empty-state large"><span>◫</span><strong>{resultQuery ? 'No visual views match this search' : 'No visual derivatives are available'}</strong><p>{isAudioResult ? 'Built-in WAV visuals or FFmpeg/SoX spectrograms appear here.' : 'Pillow-based views appear here when the optional image engine is installed.'}</p></div>}
                    </div>
                    {selectedVisual && <aside className="visual-focus"><button onClick={() => setSelectedVisual(null)} aria-label="Close visual preview">×</button>{selectedVisual.preview_url ? <SafePreviewImage src={selectedVisual.preview_url} alt={selectedVisual.title || selectedVisual.name || 'Selected visual derivative'} /> : null}<strong>{selectedVisual.title || selectedVisual.name}</strong><p>{selectedVisual.kind || 'Derived visual evidence'}</p></aside>}
                  </div>
                </section>
              )}

              {activeTab === 'metadata' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">Parsed properties</p><h2>Metadata &amp; structure</h2></div><span>Original values preserved</span></div>
                  <div className="metadata-grid">
                    {filteredMetadata.map((row) => <div key={row.path}><span>{row.path.replace(/([A-Z])/g, ' $1').replace(/_/g, ' ')}</span><strong>{row.value}</strong></div>)}
                    {!filteredMetadata.length && <div className="empty-state large"><span>◇</span><strong>{resultQuery ? 'No metadata matches this search' : 'No structured metadata was returned'}</strong><p>Raw strings and tool output remain available in the exported report.</p></div>}
                  </div>
                  {result?.structure !== undefined && <details className="raw-details"><summary>Raw structure report</summary><pre>{JSON.stringify(result.structure, null, 2)}</pre></details>}
                </section>
              )}

              {activeTab === 'hex' && (
                <section className="tab-panel hex-panel">
                  <div className="section-title"><div><p className="eyebrow">Read-only byte evidence</p><h2>Hex editor</h2></div><span>{hexView ? `${formatBytes(hexView.total_size)} · ${hexView.anomalies.length} anomalies` : 'Select an artifact'}</span></div>
                  <p className="panel-lede">Inspect raw bytes without modifying evidence. Search text or hexadecimal patterns across the complete artifact, jump to matches, and review bounded heuristic anomaly signals.</p>
                  <div className="hex-toolbar">
                    <label><span>Artifact</span><select value={effectiveHexArtifactId} onChange={(event) => selectHexArtifact(event.target.value)} disabled={!hexArtifactChoices.length}><option value="">Choose an artifact…</option>{hexArtifactChoices.map((artifact) => <option key={artifactId(artifact)} value={artifactId(artifact)}>{artifactName(artifact)} · {formatBytes(artifactSize(artifact))}</option>)}</select></label>
                    <form onSubmit={submitHexSearch} className="hex-search-form"><label><span>Search</span><input value={hexSearchInput} onChange={(event) => setHexSearchInput(event.target.value.slice(0, 256))} placeholder={hexSearchMode === 'hex' ? '89 50 4e 47 or PK:03:04' : 'flag{…} or readable text'} disabled={!effectiveHexArtifactId} /></label><select aria-label="Hex search mode" value={hexSearchMode} onChange={(event) => setHexSearchMode(event.target.value as 'text' | 'hex')} disabled={!effectiveHexArtifactId}><option value="text">Text</option><option value="hex">Hex bytes</option></select><button type="submit" disabled={!effectiveHexArtifactId || hexLoading}>Search</button></form>
                    <div className="hex-offset-control"><label><span>Offset</span><input value={hexOffsetInput} onChange={(event) => setHexOffsetInput(event.target.value.slice(0, 24))} onKeyDown={(event) => { if (event.key === 'Enter') goToHexOffset(); }} disabled={!effectiveHexArtifactId} /></label><button onClick={goToHexOffset} disabled={!effectiveHexArtifactId}>Go</button><button onClick={() => jumpToHexOffset(Math.max(0, hexOffset - 8192))} disabled={!hexView || hexOffset <= 0} aria-label="Previous hex page">←</button><button onClick={() => jumpToHexOffset(hexOffset + 8192)} disabled={!hexView || hexOffset + hexView.length >= hexView.total_size} aria-label="Next hex page">→</button></div>
                  </div>
                  {hexError && <div className="error-banner" role="alert"><span>!</span><p>{hexError}</p><button onClick={() => setHexError('')} aria-label="Dismiss hex error">×</button></div>}
                  {hexLoading && <div className="hex-loading"><span className="spinner" />Reading bytes and checking anomalies…</div>}
                  {!hexLoading && !hexArtifactChoices.length && <div className="empty-state large"><span>⌘</span><strong>No artifact is available for hex inspection</strong><p>Run an analysis first so the immutable source and recovered files can be selected.</p></div>}
                  {!hexLoading && hexView && <>
                    <div className="hex-stat-row"><div><strong>{formatHexOffset(hexView.offset)}</strong><small>window start</small></div><div><strong>{formatBytes(hexView.length)}</strong><small>bytes shown</small></div><div><strong>{hexView.search?.match_count || 0}</strong><small>search matches</small></div><div><strong>{hexView.anomalies.length}</strong><small>heuristic anomalies</small></div></div>
                    <div className="hex-layout">
                      <div className="hex-table" role="table" aria-label="Hex byte window"><div className="hex-table-head" role="row"><span>Offset</span><span>Hex bytes</span><span>ASCII</span></div>{hexView.rows.map((row) => { const matched = hexView.matches.some((match) => match.offset < row.offset + row.length && match.offset + match.length > row.offset); return <div className={`hex-row ${matched ? 'matched' : ''}`} role="row" key={row.offset}><span className="hex-row-offset">{formatHexOffset(row.offset)}</span><code>{row.hex}</code><code className="hex-row-ascii">{row.ascii}</code></div>; })}{!hexView.rows.length && <div className="hex-empty">The selected offset is at end-of-file.</div>}</div>
                      <aside className="hex-findings"><section><div className="hex-subheading"><div><p className="eyebrow">Pattern search</p><h3>Matches</h3></div><span>{hexView.matches.length}</span></div>{hexView.matches.length ? <div className="hex-match-list">{hexView.matches.map((match) => <button key={match.offset} onClick={() => jumpToHexOffset(Math.max(0, match.offset - 64))}><strong>{formatHexOffset(match.offset)}</strong><small>{match.length} byte{match.length === 1 ? '' : 's'} · jump here</small></button>)}</div> : <p className="hex-muted">{hexSearch ? 'No matches found in this artifact.' : 'Enter text or hex bytes above to search.'}</p>}</section><section><div className="hex-subheading"><div><p className="eyebrow">Automated review</p><h3>Anomalies</h3></div><span>{hexView.anomalies.length}</span></div>{hexView.anomalies.length ? <div className="hex-anomaly-list">{hexView.anomalies.map((anomaly, index) => <button key={`${anomaly.kind}-${anomaly.offset}-${index}`} onClick={() => jumpToHexOffset(Math.max(0, anomaly.offset - 64))}><div><strong>{anomaly.title}</strong><em className={anomaly.severity || 'info'}>{anomaly.severity || 'info'}</em></div><small>{formatHexOffset(anomaly.offset)} · {formatBytes(anomaly.length)}</small><p>{anomaly.description}</p></button>)}</div> : <p className="hex-muted">No heuristic anomalies were detected. This is a signal only; format-aware review still matters.</p>}</section></aside>
                    </div>
                  </>}
                </section>
              )}

              {activeTab === 'tools' && (
                <section className="tab-panel tool-results-panel">
                  <div className="section-title"><div><p className="eyebrow">Raw analyzer evidence</p><h2>Tool results</h2></div><span>{toolMethods.length} analyzers · {availableTools} external tools installed</span></div>
                  <p className="panel-lede">Every built-in and external analyzer is recorded, including clean negative checks, skipped methods, and missing tools. Command output is open by default so the evidence and diagnostics are immediately visible.</p>
                  <div className="tool-results-list">
                    {filteredToolMethods.map((method, index) => {
                      const status = methodStatusGroup(method);
                      const linkedArtifacts = (method.artifact_ids || []).map((id) => publicArtifactsByEngineId.get(id)).filter((item): item is Artifact => Boolean(item));
                      const imageArtifacts = linkedArtifacts.map((artifact) => ({ artifact, preview: artifactPreviewUrl(artifact) })).filter((item): item is { artifact: Artifact; preview: string } => Boolean(item.preview));
                      return <article className={`tool-result-card ${status}`} key={method.id || `${methodName(method)}-${index}`}>
                        <div className="tool-result-heading"><span className={`coverage-status ${method.status || 'unknown'}`}>{status === 'completed' ? '✓' : status === 'failed' ? '!' : '·'}</span><div><strong>{methodName(method)}</strong><p>{method.summary || method.error || 'No additional commentary.'}</p><small>{declaredExternalToolIds.has(method.id || method.tool_id || '') ? 'external adapter' : 'built-in analyzer'} · {method.tool?.executable || 'forensics engine'}{method.tool?.resolved ? ` · ${method.tool.resolved}` : ''}{method.tool?.version ? ` · v${method.tool.version}` : ''}{method.duration_ms !== undefined ? ` · ${formatDuration(method.duration_ms)}` : ''}{method.extracted_count ? ` · ${method.extracted_count} artifact${method.extracted_count === 1 ? '' : 's'}` : ''}</small></div><em>{methodStatusLabel(method)}</em></div>
                        {status === 'missing' && capabilitiesById.get(method.id || method.tool_id || '')?.installable ? <button className="missing-tool-link" disabled={toolInstallBusy} onClick={() => installMissingTools([method.id || method.tool_id || ''])}>{toolInstallBusy ? 'Installing…' : 'Install this tool'}</button> : null}
                        <details open className="tool-result-details"><summary>Inspect command &amp; output</summary>{method.command?.length ? <div className="tool-command"><span>Command</span><code>{method.command.join(' ')}</code></div> : null}{method.stdout ? <div className="tool-output"><span>stdout</span><pre>{boundedDisplay(method.stdout)}</pre></div> : null}{method.stderr ? <div className="tool-output"><span>stderr</span><pre>{boundedDisplay(method.stderr)}</pre></div> : null}{method.details && Object.keys(method.details).length ? <div className="tool-output"><span>details</span><pre>{boundedDisplay(JSON.stringify(method.details, null, 2))}</pre></div> : null}{method.output_truncated ? <p className="output-note">Output was capped by the configured external-output budget; the full process was not retained.</p> : null}</details>
                        {imageArtifacts.length ? <div className="tool-image-gallery"><span>{method.id === 'foremost' ? 'Foremost carved image previews' : 'Recovered image previews'} · {imageArtifacts.length}</span><div className="tool-image-grid">{imageArtifacts.map(({ artifact, preview }) => <button key={artifactId(artifact)} onClick={() => { setSelectedArtifact(artifact); setActiveTab('artifacts'); }} aria-label={`Open preview of ${artifactName(artifact)}`}><SafePreviewImage src={preview} alt={`Preview of ${artifactName(artifact)}`} /><small>{artifactName(artifact)}</small></button>)}</div></div> : null}
                        {linkedArtifacts.length ? <div className="tool-artifacts"><span>Recovered by this tool</span>{linkedArtifacts.map((artifact) => <button key={artifactId(artifact)} onClick={() => { setSelectedArtifact(artifact); setActiveTab('artifacts'); }}><strong>{artifactName(artifact)}</strong><small>{formatBytes(artifactSize(artifact))} · {artifactMediaType(artifact)}</small></button>)}</div> : null}
                      </article>;
                    })}
                    {!filteredToolMethods.length && <div className="empty-state large"><span>⌘</span><strong>{resultQuery ? 'No tool results match this search' : 'No tool results are recorded'}</strong><p>Enable analysis stages in Scan settings or start the local API to see external availability.</p></div>}
                  </div>
                </section>
              )}

              {activeTab === 'methods' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">Coverage statement</p><h2>Every applicable method</h2></div><div className="filter-pills">{(['all', 'completed', 'missing', 'skipped', 'failed'] as const).map((filter) => <button key={filter} className={methodFilter === filter ? 'active' : ''} onClick={() => setMethodFilter(filter)}>{filter}</button>)}</div></div>
                  <div className="coverage-list">
                    {filteredMethods.map((method, index) => <article key={method.id || `${methodName(method)}-${index}`}><span className={`coverage-status ${method.status || 'unknown'}`}>{methodStatusGroup(method) === 'completed' ? '✓' : methodStatusGroup(method) === 'failed' ? '!' : '·'}</span><div><strong>{methodName(method)}</strong><p>{method.summary || method.error || 'Method completed without additional commentary.'}</p><small>{method.tool?.version || method.version ? `v${method.tool?.version || method.version} · ` : ''}{formatDuration(method.duration_ms)}{method.findings !== undefined ? ` · ${method.findings} findings` : ''}</small>{(method.command?.length || method.stdout || method.stderr || method.details) ? <details open className="method-details"><summary>Inspect output</summary>{method.command?.length ? <code>{method.command.join(' ')}</code> : null}{method.stdout ? <pre>{boundedDisplay(method.stdout)}</pre> : null}{method.stderr ? <pre>{boundedDisplay(method.stderr)}</pre> : null}{method.details ? <pre>{boundedDisplay(JSON.stringify(method.details, null, 2))}</pre> : null}</details> : null}</div><em>{methodStatusLabel(method)}</em></article>)}
                    {!filteredMethods.length && <div className="empty-state large"><span>⌘</span><strong>No coverage records match these filters</strong><p>Clear the search or choose another status filter.</p></div>}
                  </div>
                  {result?.logs?.length ? <details className="raw-details"><summary>Sanitized tool logs</summary><pre>{JSON.stringify(result.logs, null, 2)}</pre></details> : null}
                </section>
              )}
            </div>
          </>
        )}
      </section>

      {showAdvanced && (
        <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setShowAdvanced(false)}>
          <section className="method-modal" role="dialog" aria-modal="true" aria-labelledby="method-title">
            <header><div><p className="eyebrow">Scan configuration</p><h2 id="method-title">Choose exactly what will run</h2></div><button onClick={() => setShowAdvanced(false)} aria-label="Close scan settings">×</button></header>
            <p className="modal-intro">Settings are validated by the local engine and saved with the case. Fingerprinting and raw string recovery always run so every result keeps a trustworthy evidence baseline.</p>
            <div className="method-catalog settings-catalog">
              <section className="settings-section" aria-labelledby="analysis-switches">
                <div className="settings-section-title"><div><p className="eyebrow">Analysis stages</p><h3 id="analysis-switches">{evidenceSection === 'audio' ? 'Audio method groups' : 'Image method groups'}</h3></div><span>{(evidenceSection === 'audio' ? audioConfigurableMethods : configurableMethods).filter((item) => scanOptions[item.key]).length}/{(evidenceSection === 'audio' ? audioConfigurableMethods : configurableMethods).length} enabled</span></div>
                <div className="method-settings-grid">
                  {(evidenceSection === 'audio' ? audioConfigurableMethods : configurableMethods).map((item) => <label className="setting-toggle" key={item.key}><span><strong>{item.title}</strong><small>{item.copy}</small></span><input type="checkbox" checked={scanOptions[item.key]} onChange={(event) => setScanOptions((current) => ({ ...current, [item.key]: event.target.checked }))} /><i aria-hidden="true" /></label>)}
                </div>
              </section>

              <section className="settings-section" aria-labelledby="safety-budgets">
                <div className="settings-section-title"><div><p className="eyebrow">Resource controls</p><h3 id="safety-budgets">Safety budgets</h3></div><button onClick={() => setScanOptions(profileOptionDefaults[profile])}>Reset {profile}</button></div>
                <div className="budget-settings">
                  <label><span>Recursion depth<small>Nested extraction levels</small></span><select value={scanOptions.max_recursion_depth} onChange={(event) => setScanOptions((current) => ({ ...current, max_recursion_depth: Number(event.target.value) }))}>{[1, 2, 3, 4].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                  <label><span>Artifact ceiling<small>25–500 derived records</small></span><input type="number" min="25" max="500" step="5" value={scanOptions.max_artifacts} onChange={(event) => setScanOptions((current) => ({ ...current, max_artifacts: Math.max(25, Math.min(500, Number(event.target.value) || 25)) }))} /></label>
                  <label><span>Tool timeout<small>Seconds per external tool</small></span><input type="number" min="5" max="180" step="5" value={scanOptions.tool_timeout_seconds} onChange={(event) => setScanOptions((current) => ({ ...current, tool_timeout_seconds: Math.max(5, Math.min(180, Number(event.target.value) || 5)) }))} /></label>
                  <label><span>External output<small>KiB retained per tool</small></span><input type="number" min="64" max="2048" step="64" value={scanOptions.external_output_kib} onChange={(event) => setScanOptions((current) => ({ ...current, external_output_kib: Math.max(64, Math.min(2048, Number(event.target.value) || 64)) }))} /></label>
                  <label><span>Extracted files<small>Maximum child files per tool</small></span><input type="number" min="1" max="64" step="1" value={scanOptions.max_external_files} onChange={(event) => setScanOptions((current) => ({ ...current, max_external_files: Math.max(1, Math.min(64, Number(event.target.value) || 1)) }))} /></label>
                  <label><span>Foremost depth<small>Recursively carve recovered files</small></span><select value={scanOptions.foremost_depth} onChange={(event) => setScanOptions((current) => ({ ...current, foremost_depth: Math.max(1, Math.min(4, Number(event.target.value))) }))}><option value={1}>1 · Source only</option><option value={2}>2 · One recovered level</option><option value={3}>3 · Two recovered levels</option><option value={4}>4 · Maximum bounded depth</option></select></label>
                  {evidenceSection === 'image' ? <>
                    <label><span>Color remaps<small>Three-tone visual variants</small></span><select value={scanOptions.color_remap_variants} onChange={(event) => setScanOptions((current) => ({ ...current, color_remap_variants: Number(event.target.value) }))}>{[0, 2, 4, 6, 8].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                    <label><span>OCR language<small>Tesseract language code</small></span><input value={scanOptions.ocr_language} maxLength={64} pattern="[A-Za-z0-9_+\-]+" onChange={(event) => setScanOptions((current) => ({ ...current, ocr_language: event.target.value.replace(/[^A-Za-z0-9_+\-]/g, '').slice(0, 64) || 'eng' }))} /></label>
                    <label><span>zsteg mode<small>All combos or only LSB planes</small></span><select value={scanOptions.zsteg_mode} onChange={(event) => setScanOptions((current) => ({ ...current, zsteg_mode: event.target.value as ScanOptions['zsteg_mode'] }))}><option value="all">All checks (zsteg -a)</option><option value="lsb">LSB only (zsteg --lsb)</option></select></label>
                  </> : <>
                    <label><span>Analyze duration<small>Decoded seconds, bounded 15–300</small></span><input type="number" min="15" max="300" step="15" value={scanOptions.audio_analysis_seconds} onChange={(event) => setScanOptions((current) => ({ ...current, audio_analysis_seconds: Math.max(15, Math.min(300, Number(event.target.value) || 15)) }))} /></label>
                    <label><span>Spectrogram FFT<small>Frequency/time resolution</small></span><select value={scanOptions.audio_spectrogram_fft} onChange={(event) => setScanOptions((current) => ({ ...current, audio_spectrogram_fft: Number(event.target.value) as ScanOptions['audio_spectrogram_fft'] }))}>{[256, 512, 1024, 2048, 4096].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                    <label><span>Analysis channel<small>Signal used by decoders</small></span><select value={scanOptions.audio_channel_mode} onChange={(event) => setScanOptions((current) => ({ ...current, audio_channel_mode: event.target.value as ScanOptions['audio_channel_mode'] }))}><option value="mix">Mono mix</option><option value="left">Left</option><option value="right">Right</option><option value="difference">Stereo difference</option></select></label>
                    <label><span>PCM LSB planes<small>Least-significant sample bits</small></span><select value={scanOptions.audio_lsb_bits} onChange={(event) => setScanOptions((current) => ({ ...current, audio_lsb_bits: Number(event.target.value) }))}>{[1, 2, 3, 4].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                  </>}
                </div>
              </section>

              <section className="settings-section" aria-labelledby="external-tools">
                <div className="settings-section-title"><div><p className="eyebrow">Installed integrations</p><h3 id="external-tools">{evidenceSection === 'audio' ? 'Audio tool adapters' : 'Image tool adapters'}</h3></div><div className="tool-header-actions"><span>{availableTools}/{relevantCapabilities.length} installed</span><button onClick={refreshToolAvailability} disabled={toolRefreshBusy || toolInstallBusy}>{toolRefreshBusy ? 'Checking…' : 'Refresh availability'}</button><button onClick={() => installMissingTools()} disabled={toolInstallBusy || toolRefreshBusy || !relevantCapabilities.length}>{toolInstallBusy ? 'Installing tools…' : 'Install all missing'}</button></div></div>
                <p className="install-note">One click installs fixed, allowlisted packages non-interactively through Kali WSL or Windows Package Manager—no ZIP extraction or installer walkthrough. {evidenceSection === 'audio' ? 'Audio coverage includes FFmpeg/FFprobe, SoX, MediaInfo, minimodem and multimon-ng.' : 'Availability is refreshed automatically when installation finishes.'}</p>
                {toolInstallReport && <div className={`tool-download-report ${toolInstallReport.status || ''}`}><div><strong>{toolInstallReport.message || 'Tool installation finished.'}</strong><small>{toolInstallReport.available_count !== undefined ? `${toolInstallReport.available_count}/${toolInstallReport.requested_count || 0} requested tools detected` : 'Installation report recorded.'}{toolInstallReport.managers?.length ? ` · ${toolInstallReport.managers.join(', ')}` : ''}</small></div></div>}
                {toolInstallReport?.items?.length ? <div className="tool-download-items" aria-label="Tool installation status"><span className="tool-download-items-title">Installation results</span>{toolInstallReport.items.map((item, index) => <div className="tool-download-item" key={`${item.id || 'tool'}-${index}`}><span><strong>{item.id || 'tool'}</strong><small>{item.message || item.status || 'recorded'}{item.channel ? ` · ${item.channel}` : ''}{item.resolved ? ` · ${item.resolved}` : ''}</small>{item.diagnostic ? <details open><summary>Installer diagnostic</summary><pre>{boundedDisplay(item.diagnostic, 2_000)}</pre></details> : null}</span><em className={item.status || ''}>{(item.status || 'unknown').replaceAll('_', ' ')}</em></div>)}</div> : null}
                <div className="tool-selection-actions"><button onClick={() => setScanOptions((current) => ({ ...current, selected_external_tools: Array.from(new Set([...(current.selected_external_tools || []), ...relevantCapabilities.map((item) => item.id).filter((item): item is string => Boolean(item))])) }))}>Select visible</button><button onClick={() => setScanOptions((current) => ({ ...current, selected_external_tools: (current.selected_external_tools || capabilities.map((item) => item.id).filter((item): item is string => Boolean(item))).filter((id) => !relevantCapabilities.some((item) => item.id === id)) }))}>Clear visible</button></div>
                <div className="external-tool-grid">
                  {relevantCapabilities.map((capability) => {
                    const id = capability.id || capability.executable || capability.name || '';
                    const selected = scanOptions.selected_external_tools === null || scanOptions.selected_external_tools.includes(id);
                    const location = capability.resolved || capability.install_hint;
                    return <label key={id} className={!capability.available ? 'missing' : ''} title={location || undefined}><input type="checkbox" disabled={!scanOptions.external_tools} checked={selected} onChange={(event) => toggleExternalTool(id, event.target.checked)} /><span><strong>{capability.name || id}</strong><small>{capability.category || 'forensics'} · {(capability.formats || ['all']).join(', ')}{capability.available ? ` · ${capability.source || 'native'} · ${capability.resolved || 'detected'}` : capability.install_strategy ? ` · ${capability.install_strategy}` : ''}</small></span><em>{capability.available ? 'Installed' : capability.installable ? 'Ready to install' : 'Unavailable'}</em>{!capability.available && capability.installable ? <button className="tool-download" disabled={toolInstallBusy} onClick={(event) => { event.preventDefault(); event.stopPropagation(); installMissingTools([id]); }}>Install</button> : null}</label>;
                  })}
                  {!capabilities.length && <p className="tool-empty">Start the local API to inspect optional tool availability.</p>}
                </div>
              </section>
            </div>
            <footer><div><span className="status-dot" /><p><strong>{configurableMethods.filter((item) => scanOptions[item.key]).length} method groups enabled</strong><small>{scanOptions.max_artifacts} artifacts · {scanOptions.max_recursion_depth} levels · Foremost depth {scanOptions.foremost_depth} · {scanOptions.tool_timeout_seconds}s/tool · zsteg {scanOptions.zsteg_mode === 'lsb' ? '--lsb' : '-a'}</small></p></div><button onClick={() => setShowAdvanced(false)}>Apply settings</button></footer>
          </section>
        </div>
      )}
    </main>
  );
}

// Browser extensions can inject nodes into the server-rendered document before
// React hydrates it. Keep the SSR snapshot deliberately small and stable, then
// mount the interactive workbench on the client after hydration has completed.
const subscribeToNothing = () => () => {};
const getClientSnapshot = () => true;
const getServerSnapshot = () => false;

export default function Home() {
  const hydrated = useSyncExternalStore(subscribeToNothing, getClientSnapshot, getServerSnapshot);
  if (!hydrated) {
    return <main className="app-shell app-shell-loading" aria-busy="true" suppressHydrationWarning><div><span className="loading-mark">F</span><p>Loading forensic workbench…</p></div></main>;
  }
  return <HomeWorkbench />;
}
