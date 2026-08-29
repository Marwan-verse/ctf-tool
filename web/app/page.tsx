'use client';

import { type CSSProperties, type ClipboardEvent, type DragEvent, type FormEvent, type KeyboardEvent, type MouseEvent as ReactMouseEvent, useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';

type Profile = 'quick' | 'balanced' | 'deep';
type EvidenceSection = 'image' | 'audio' | 'corrupted';
type Screen = 'setup' | 'running' | 'results';
type FileDetection = { label: string; source: 'content' | 'browser' | 'extension' | 'scanning' };
type ColorTheme = 'light' | 'dark';
type UiPreferences = { theme: ColorTheme; zoom: number };
type ResultTab = 'overview' | 'repairs' | 'audio' | 'candidates' | 'artifacts' | 'visual' | 'metadata' | 'hex' | 'tools' | 'methods';
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
  evidence_type: 'auto' | 'image' | 'audio' | 'corrupted';
  audio_spectrogram: boolean;
  audio_signal_decoders: boolean;
  audio_sstv: boolean;
  audio_sstv_mode: 'auto' | 'robot36' | 'robot72' | 'martin1' | 'martin2' | 'scottie1' | 'scottie2' | 'scottiedx' | 'pd120' | 'pd180' | 'pd240';
  audio_sstv_max_images: number;
  audio_sstv_slant_correction: boolean;
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

type HexRow = { offset: number; hex: string; ascii: string; bytes?: number[]; length: number };
type HexMatch = { offset: number; length: number };
type HexAnomaly = { kind: string; title: string; description: string; offset: number; length: number; severity?: string; details?: Record<string, unknown> };
type HexIntegrityIssue = { kind: string; title: string; description: string; severity: 'error' | 'warning' | 'info'; offset?: number; length?: number; expected?: string; actual?: string; details?: Record<string, unknown> };
type HexRepairCandidate = { id: string; label: string; reason: string; transformation: string; producer?: string; format?: string; source_size: number; repaired_size: number; size_delta: number; changed_bytes: number; changed_offsets: number[]; after_integrity?: HexIntegrity };
type HexIntegrity = { verdict: 'valid' | 'warning' | 'corrupt' | 'unknown'; expected_format?: string | null; detected_format?: string | null; validation_format?: string | null; validation_complete?: boolean; summary: string; issues: HexIntegrityIssue[]; checks?: Array<{ id: string; status: string; summary: string }>; repair_candidates?: HexRepairCandidate[] };
type HexView = {
  artifact?: Artifact;
  offset: number;
  length: number;
  total_size: number;
  rows: HexRow[];
  matches: HexMatch[];
  anomalies: HexAnomaly[];
  integrity?: HexIntegrity;
  search?: { query?: string; mode?: string; byte_length?: number; match_count?: number };
  anomaly_scan?: { enabled?: boolean; count?: number; bounded?: boolean };
};
type HexEdit = { offset: number; original: number; value: number };
type HexEditActionItem = { offset: number; original: number; before: number; after: number };
type HexEditAction = HexEditActionItem[];
type HexContextMenu = { x: number; y: number; offset: number; original: number; value: number; blockStart: number; blockLength: number };
type HexEditPreview = {
  revision: number;
  edited_size: number;
  edit_count: number;
  sha256?: string;
  original_sha256?: string;
  artifact?: Artifact;
  integrity: HexIntegrity;
  preview: { kind: 'image' | 'audio' | 'none'; available?: boolean; media_type?: string; url?: string; message?: string };
};
type HexFormatReference = { format: string; extensions: string; header: string; trailer: string; structure: string; notes: string };
const HEX_FORMAT_REFERENCE: HexFormatReference[] = [
  { format: 'PNG', extensions: '.png', header: '89 50 4E 47 0D 0A 1A 0A', trailer: '49 45 4E 44 AE 42 60 82', structure: '4-byte length + 4-byte type + data + CRC-32', notes: 'IEND is the terminal chunk; data after it may be an embedded payload.' },
  { format: 'JPEG', extensions: '.jpg · .jpeg', header: 'FF D8 FF', trailer: 'FF D9', structure: 'FF marker + big-endian 2-byte segment length', notes: 'Scan data uses byte stuffing; EOI can be missing after a truncated transfer.' },
  { format: 'GIF', extensions: '.gif', header: 'GIF87a / GIF89a', trailer: '3B', structure: 'Blocks: 2C image, 21 extension, 3B trailer', notes: 'Image and extension payloads use length-prefixed sub-blocks.' },
  { format: 'BMP', extensions: '.bmp', header: '42 4D (BM)', trailer: 'No fixed marker', structure: '14-byte file header + DIB header + pixel offset', notes: 'bfSize and pixel offset are little-endian integrity anchors; 32-bit word lanes are checked for interleaved payloads.' },
  { format: 'WebP', extensions: '.webp', header: '52 49 46 46 ?? ?? ?? ?? 57 45 42 50', trailer: 'RIFF declared size', structure: '4CC chunk + little-endian 4-byte size + payload', notes: 'VP8, VP8L, or VP8X must appear inside the RIFF form.' },
  { format: 'TIFF', extensions: '.tif · .tiff', header: '49 49 2A 00 / 4D 4D 00 2A', trailer: 'No fixed marker', structure: 'IFD offset chain; byte order is declared in the header', notes: 'Missing IFD offsets are structural damage; there is no universal end signature.' },
  { format: 'ICO', extensions: '.ico', header: '00 00 01 00', trailer: 'No fixed marker', structure: 'Directory entries + embedded PNG/DIB image blobs', notes: 'Use embedded image signatures and directory offsets to locate payloads.' },
  { format: 'WAV', extensions: '.wav', header: '52 49 46 46 ?? ?? ?? ?? 57 41 56 45', trailer: 'RIFF declared size', structure: 'fmt/data RIFF chunks with little-endian sizes', notes: 'fmt and data chunks plus block alignment must agree for playback.' },
];

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
  parameters?: Record<string, unknown>;
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
  source?: {
    artifact_id?: string;
    name?: string;
    size?: number;
    sha256?: string;
    detected_type?: string;
    mime_type?: string;
    extension?: string;
    extension_matches_content?: boolean;
    inspected_bytes?: number;
    inspection_truncated?: boolean;
    first_32_bytes_hex?: string;
  };
  audio_analysis?: {
    metadata?: { properties?: Record<string, unknown>; statistics?: Record<string, unknown>; container?: Record<string, unknown> };
    signals?: {
      frequency_peaks?: Array<{ frequency_hz?: number; relative_db?: number }>;
      silent_segments?: Array<{ start_seconds?: number; end_seconds?: number; duration_seconds?: number }>;
      ultrasonic_energy_ratio?: number;
      dtmf?: { symbols?: string; events?: Array<Record<string, unknown>> };
      morse?: { text?: string; pattern?: string; events?: Array<Record<string, unknown>> };
      sstv?: { candidate?: boolean; status?: string; images_decoded?: number; decoded_modes?: string[]; leader_frames?: number; sync_frames?: number; sync_offsets_seconds?: number[]; headers?: Array<{ offset_seconds?: number; image_start_seconds?: number; vis_code?: number; vis_hex?: string; mode?: string | null; parity_valid?: boolean; confidence?: number; frequency_shift_hz?: number }>; requested_mode?: string; slant_correction?: boolean; method?: string };
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

type Capability = { id?: string; name?: string; executable?: string; available?: boolean; resolved?: string | null; source?: string | null; source_url?: string | null; version?: string; category?: string; profiles?: string[]; formats?: string[]; install_hint?: string; installable?: boolean; install_strategy?: string | null };
type ToolInstallReport = { status?: string; installed_count?: number; already_available_count?: number; available_count?: number; requested_count?: number; unresolved_count?: number; managers?: string[]; message?: string; items?: Array<{ id?: string; status?: string; message?: string; channel?: string | null; source?: string | null; resolved?: string | null; diagnostic?: string | null }> };
type ActivityItem = { at: string; message: string; stage?: string };
type MetadataRow = { path: string; value: string };

const API_BASE = (
  process.env.NEXT_PUBLIC_API_URL
  || (typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:8000` : 'http://localhost:8000')
).replace(/\/$/, '');
const UI_PREFERENCES_KEY = 'forenscope.ui-preferences.v1';
const DEFAULT_UI_PREFERENCES: UiPreferences = { theme: 'light', zoom: 100 };
const UI_ZOOM_MIN = 100;
const UI_ZOOM_MAX = 160;
const TERMINAL = new Set(['completed', 'succeeded', 'partial', 'failed', 'cancelled', 'expired']);

function normalizeInterfaceZoom(value: unknown) {
  const numeric = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(numeric)) return DEFAULT_UI_PREFERENCES.zoom;
  return Math.max(UI_ZOOM_MIN, Math.min(UI_ZOOM_MAX, Math.round(numeric / 5) * 5));
}

function readUiPreferences(): UiPreferences {
  if (typeof window === 'undefined') return DEFAULT_UI_PREFERENCES;
  try {
    const parsed = JSON.parse(window.localStorage.getItem(UI_PREFERENCES_KEY) || '{}') as Partial<UiPreferences>;
    return {
      theme: parsed.theme === 'dark' ? 'dark' : 'light',
      zoom: normalizeInterfaceZoom(parsed.zoom),
    };
  } catch {
    return DEFAULT_UI_PREFERENCES;
  }
}
const profileOptionDefaults: Record<Profile, ScanOptions> = {
  quick: { structure_analysis: true, visual_analysis: true, lsb_analysis: true, ocr: true, barcodes: true, recursive_extraction: true, decoders: true, crypto_analysis: true, repairs: true, external_tools: true, external_extraction: true, evidence_type: 'auto', audio_spectrogram: true, audio_signal_decoders: true, audio_sstv: true, audio_sstv_mode: 'auto', audio_sstv_max_images: 1, audio_sstv_slant_correction: true, audio_channel_exports: true, audio_audacity_bundle: true, audio_analysis_seconds: 60, audio_spectrogram_fft: 1024, audio_channel_mode: 'mix', audio_lsb_bits: 1, max_recursion_depth: 2, max_artifacts: 45, tool_timeout_seconds: 20, external_output_kib: 512, max_external_files: 16, foremost_depth: 1, color_remap_variants: 4, zsteg_mode: 'all', ocr_language: 'eng', selected_external_tools: null },
  balanced: { structure_analysis: true, visual_analysis: true, lsb_analysis: true, ocr: true, barcodes: true, recursive_extraction: true, decoders: true, crypto_analysis: true, repairs: true, external_tools: true, external_extraction: true, evidence_type: 'auto', audio_spectrogram: true, audio_signal_decoders: true, audio_sstv: true, audio_sstv_mode: 'auto', audio_sstv_max_images: 2, audio_sstv_slant_correction: true, audio_channel_exports: true, audio_audacity_bundle: true, audio_analysis_seconds: 180, audio_spectrogram_fft: 2048, audio_channel_mode: 'mix', audio_lsb_bits: 2, max_recursion_depth: 3, max_artifacts: 100, tool_timeout_seconds: 60, external_output_kib: 1024, max_external_files: 32, foremost_depth: 2, color_remap_variants: 8, zsteg_mode: 'all', ocr_language: 'eng', selected_external_tools: null },
  deep: { structure_analysis: true, visual_analysis: true, lsb_analysis: true, ocr: true, barcodes: true, recursive_extraction: true, decoders: true, crypto_analysis: true, repairs: true, external_tools: true, external_extraction: true, evidence_type: 'auto', audio_spectrogram: true, audio_signal_decoders: true, audio_sstv: true, audio_sstv_mode: 'auto', audio_sstv_max_images: 4, audio_sstv_slant_correction: true, audio_channel_exports: true, audio_audacity_bundle: true, audio_analysis_seconds: 300, audio_spectrogram_fft: 4096, audio_channel_mode: 'mix', audio_lsb_bits: 4, max_recursion_depth: 4, max_artifacts: 220, tool_timeout_seconds: 180, external_output_kib: 2048, max_external_files: 64, foremost_depth: 4, color_remap_variants: 8, zsteg_mode: 'all', ocr_language: 'eng', selected_external_tools: null },
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
  { key: 'audio_sstv', title: 'SSTV image recovery', copy: 'Decode VIS, Robot, Martin, Scottie and PD beeps into recovered PNG images.' },
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
const repairConfigurableMethods: Array<{ key: BooleanOptionKey; title: string; copy: string }> = [
  { key: 'structure_analysis', title: 'Structure validation', copy: 'Verify signatures, headers, checksums, indexes, lengths and end markers.' },
  { key: 'recursive_extraction', title: 'Carving & recursion', copy: 'Recover embedded signatures, archive members and nested child files.' },
  { key: 'decoders', title: 'Encoding recovery', copy: 'Expand bounded Base encodings and compressed transform chains.' },
  { key: 'crypto_analysis', title: 'Encrypted payload recovery', copy: 'Inspect carved data and try a supplied passphrase on bounded payloads.' },
  { key: 'repairs', title: 'Non-destructive repairs', copy: 'Write separate, hashed repair candidates without changing the source.' },
  { key: 'external_tools', title: 'Recovery tool adapters', copy: 'Run applicable validators, carvers and format tools in bounded subprocesses.' },
  { key: 'external_extraction', title: 'Recovered file output', copy: 'Allow tools to retain bounded child files and normalized copies.' },
];
const repairMethodGroups = [
  { title: 'Identify', copy: 'Magic bytes, hashes, type mismatch', tone: 1 },
  { title: 'Validate', copy: 'Headers, checksums, indexes, EOF', tone: 2 },
  { title: 'Recover', copy: 'Carving, archives, nested payloads', tone: 3 },
  { title: 'Repair', copy: 'Copy-only fixes and re-validation', tone: 4 },
];
const SECTION_COPY: Record<EvidenceSection, {
  label: string;
  symbol: string;
  setupEyebrow: string;
  headline: string;
  dropTitle: string;
  formatCopy: string;
  accept?: string;
  analyzeLabel: string;
  selectedNote: string;
  passwordHint: string;
  resultEyebrow: string;
  fallbackName: string;
  settingsLabel: string;
  toolLabel: string;
  installNote: string;
}> = {
  image: {
    label: 'Image', symbol: '◫', setupEyebrow: 'Image forensics', headline: 'Find what the pixels are hiding.',
    dropTitle: 'Drop an image here', formatCopy: 'PNG, JPEG, GIF, BMP, WebP, SVG, TIFF or ICO',
    accept: '.png,.apng,.jpg,.jpeg,.gif,.bmp,.webp,.svg,.tif,.tiff,.ico,image/svg+xml,application/octet-stream',
    analyzeLabel: 'Analyze image', selectedNote: 'Preview waits for the sandboxed safe renderer',
    passwordHint: 'Steghide automatically tries an empty passphrase when this is omitted; Stegseek and OutGuess use a supplied value for bounded extraction. Encrypted payload checks support OpenSSL salted AES and passphrase-based XOR.',
    resultEyebrow: 'Investigation complete', fallbackName: 'Image scan', settingsLabel: 'Image', toolLabel: 'Image',
    installNote: 'Availability is refreshed automatically when installation finishes.',
  },
  audio: {
    label: 'Audio', symbol: '≋', setupEyebrow: 'Audio forensics', headline: 'Hear what the waveform is hiding.',
    dropTitle: 'Drop an audio file here', formatCopy: 'WAV, MP3, FLAC, Ogg/Opus, M4A, AIFF, AU, WMA, AMR, CAF or MIDI',
    accept: '.wav,.wave,.mp3,.flac,.ogg,.oga,.opus,.m4a,.aac,.aif,.aiff,.aifc,.au,.snd,.wma,.amr,.caf,.mid,.midi,audio/*,application/octet-stream',
    analyzeLabel: 'Analyze audio', selectedNote: 'Playback uses only content-verified local audio',
    passwordHint: 'Steghide automatically tries an empty passphrase for WAV/AU payloads; extracted PCM bits and carved data also enter bounded encrypted-payload recovery.',
    resultEyebrow: 'Audio investigation complete', fallbackName: 'Audio scan', settingsLabel: 'Audio', toolLabel: 'Audio',
    installNote: 'Audio coverage includes FFmpeg/FFprobe, SoX, MediaInfo, minimodem and multimon-ng.',
  },
  corrupted: {
    label: 'Corrupted files', symbol: '⌁', setupEyebrow: 'Corrupted-file recovery', headline: 'Recover what the file forgot.',
    dropTitle: 'Drop a damaged file here', formatCopy: 'PDF, ZIP, Office, image, archive or unknown binary',
    analyzeLabel: 'Diagnose & recover', selectedNote: 'Every repair is a separate, hashed evidence artifact',
    passwordHint: 'Used only for bounded archive, embedded-payload and encrypted-data recovery; it is never saved with the case.',
    resultEyebrow: 'Recovery investigation complete', fallbackName: 'Corrupted-file scan', settingsLabel: 'Recovery', toolLabel: 'Recovery',
    installNote: 'General validators, Binwalk, Foremost and 7-Zip are selected by the detected content type.',
  },
};
const profiles: Array<{ id: Profile; symbol: string; name: string; copy: string; tag: string }> = [
  { id: 'quick', symbol: '↯', name: 'Quick', copy: 'Core clues with minimal transforms', tag: 'Fast' },
  { id: 'balanced', symbol: '✦', name: 'Balanced', copy: 'Best coverage for most CTFs', tag: 'Recommended' },
  { id: 'deep', symbol: '◎', name: 'Deep', copy: 'Carving, recursion and repairs', tag: 'Thorough' },
];
const resultTabs: Array<{ id: ResultTab; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'repairs', label: 'Repair lab' },
  { id: 'audio', label: 'Audio lab' },
  { id: 'candidates', label: 'Flag candidates' },
  { id: 'artifacts', label: 'Artifacts' },
  { id: 'visual', label: 'Visual lab' },
  { id: 'metadata', label: 'Metadata' },
  { id: 'hex', label: 'Hex view' },
  { id: 'tools', label: 'Tool results' },
  { id: 'methods', label: 'Coverage & logs' },
];

function clientFileTypeFromBytes(bytes: Uint8Array, file: File): FileDetection {
  const startsWith = (...values: number[]) => values.every((value, index) => bytes[index] === value);
  const ascii = (offset = 0, length = 64) => new TextDecoder().decode(bytes.slice(offset, offset + length));
  const extension = file.name.includes('.') ? file.name.split('.').pop()?.toLowerCase() : '';
  const extensionLabels: Record<string, string> = {
    jpg: 'JPEG image', jpeg: 'JPEG image', png: 'PNG image', apng: 'APNG image', gif: 'GIF image',
    bmp: 'BMP image', webp: 'WebP image', svg: 'SVG document', tif: 'TIFF image', tiff: 'TIFF image', ico: 'ICO image',
    wav: 'WAV audio', wave: 'WAV audio', mp3: 'MP3 audio', flac: 'FLAC audio', ogg: 'Ogg audio', opus: 'Opus audio',
    m4a: 'M4A / AAC audio', aac: 'AAC audio', aif: 'AIFF audio', aiff: 'AIFF audio', au: 'AU audio', snd: 'AU audio',
    wma: 'WMA audio', amr: 'AMR audio', caf: 'CAF audio', mid: 'MIDI file', midi: 'MIDI file',
    pdf: 'PDF document', zip: 'ZIP archive', docx: 'ZIP / Office container', xlsx: 'ZIP / Office container', pptx: 'ZIP / Office container',
    '7z': '7-Zip archive', rar: 'RAR archive', tar: 'TAR archive', gz: 'GZip stream', bz2: 'BZip2 stream', xz: 'XZ stream', zst: 'Zstandard stream',
    pcap: 'PCAP capture', pcapng: 'PCAPNG capture', db: 'SQLite database', sqlite: 'SQLite database', sqlite3: 'SQLite database',
    eml: 'RFC 5322 email', rtf: 'RTF document', evtx: 'Windows EVTX log', pst: 'Outlook PST store', ost: 'Outlook OST store',
    e01: 'EWF / E01 disk image', raw: 'Raw disk or memory image', img: 'Raw disk image', dd: 'Raw disk image', vmem: 'Memory dump', dmp: 'Memory or crash dump',
  };

  if (startsWith(0x89, 0x50, 0x4e, 0x47)) return { label: 'PNG image', source: 'content' };
  if (startsWith(0xff, 0xd8, 0xff)) return { label: 'JPEG image', source: 'content' };
  if (ascii(0, 6) === 'GIF87a' || ascii(0, 6) === 'GIF89a') return { label: 'GIF image', source: 'content' };
  if (startsWith(0x42, 0x4d)) return { label: 'BMP image', source: 'content' };
  if (ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WEBP') return { label: 'WebP image', source: 'content' };
  if (ascii(0, 4) === 'RIFF' && ascii(8, 4) === 'WAVE') return { label: 'WAV audio', source: 'content' };
  if (startsWith(0x49, 0x44, 0x33) || (bytes[0] === 0xff && (bytes[1] & 0xe0) === 0xe0)) return { label: 'MP3 audio', source: 'content' };
  if (ascii(0, 4) === 'fLaC') return { label: 'FLAC audio', source: 'content' };
  if (ascii(0, 4) === 'OggS') return { label: 'Ogg audio', source: 'content' };
  if (ascii(0, 4) === '%PDF') return { label: 'PDF document', source: 'content' };
  if (startsWith(0x50, 0x4b, 0x03, 0x04) || startsWith(0x50, 0x4b, 0x05, 0x06) || startsWith(0x50, 0x4b, 0x07, 0x08)) return { label: 'ZIP archive / Office container', source: 'content' };
  if (startsWith(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c)) return { label: '7-Zip archive', source: 'content' };
  if (startsWith(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07)) return { label: 'RAR archive', source: 'content' };
  if (startsWith(0x1f, 0x8b)) return { label: 'GZip stream', source: 'content' };
  if (startsWith(0x42, 0x5a, 0x68)) return { label: 'BZip2 stream', source: 'content' };
  if (startsWith(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)) return { label: 'XZ stream', source: 'content' };
  if (startsWith(0x28, 0xb5, 0x2f, 0xfd)) return { label: 'Zstandard stream', source: 'content' };
  if (ascii(257, 5) === 'ustar') return { label: 'TAR archive', source: 'content' };
  if (ascii(0, 16) === 'SQLite format 3\u0000') return { label: 'SQLite database', source: 'content' };
  if (startsWith(0xd4, 0xc3, 0xb2, 0xa1) || startsWith(0xa1, 0xb2, 0xc3, 0xd4) || startsWith(0x4d, 0x3c, 0xb2, 0xa1) || startsWith(0xa1, 0xb2, 0x3c, 0x4d)) return { label: 'PCAP capture', source: 'content' };
  if (startsWith(0x0a, 0x0d, 0x0d, 0x0a)) return { label: 'PCAPNG capture', source: 'content' };
  if (startsWith(0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1)) return { label: 'OLE / legacy Office document', source: 'content' };
  if (ascii(0, 5) === '{\\rtf') return { label: 'RTF document', source: 'content' };
  if (ascii(0, 7) === 'ElfFile') return { label: 'Windows EVTX log', source: 'content' };
  if (ascii(0, 4) === 'regf') return { label: 'Windows registry hive', source: 'content' };
  if (ascii(0, 4) === '!BDN') return { label: 'Outlook PST / OST store', source: 'content' };
  if (startsWith(0x7f, 0x45, 0x4c, 0x46)) return { label: 'ELF executable', source: 'content' };
  if (startsWith(0x4d, 0x5a)) return { label: 'Windows PE executable', source: 'content' };
  if (ascii(0, 4) === 'MThd') return { label: 'MIDI file', source: 'content' };
  if (ascii(0, 5).trimStart().startsWith('<svg')) return { label: 'SVG image', source: 'content' };
  if (/^(From:|Received:|MIME-Version:|Subject:)/m.test(ascii(0, 1024))) return { label: 'RFC 5322 email', source: 'content' };
  if (file.type) return { label: file.type, source: 'browser' };
  if (extension && extensionLabels[extension]) return { label: extensionLabels[extension], source: 'extension' };
  return { label: 'Unknown binary / text file', source: 'content' };
}

async function detectClientFileType(file: File): Promise<FileDetection> {
  const bytes = new Uint8Array(await file.slice(0, 64 * 1024).arrayBuffer());
  return clientFileTypeFromBytes(bytes, file);
}

function getJobId(job: Job | null) { return job?.id || job?.job_id || ''; }
function jobName(job: Job | null) { return job?.original_filename || job?.original_name || job?.filename || ''; }
function sectionForJob(job: Job | null): EvidenceSection {
  if (job?.result?.section === 'corrupted' || job?.options?.evidence_type === 'corrupted') return 'corrupted';
  if (job?.result?.section === 'audio' || job?.options?.evidence_type === 'audio') return 'audio';
  return 'image';
}
function configurableMethodsFor(section: EvidenceSection) {
  if (section === 'audio') return audioConfigurableMethods;
  if (section === 'corrupted') return repairConfigurableMethods;
  return configurableMethods;
}
function methodGroupsFor(section: EvidenceSection) {
  if (section === 'audio') return audioMethodGroups;
  if (section === 'corrupted') return repairMethodGroups;
  return methodGroups;
}
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
function artifactRepairDetails(artifact: Artifact) {
  const lineage = artifact.metadata?.lineage;
  const entry = Array.isArray(lineage) && lineage[0] && typeof lineage[0] === 'object'
    ? lineage[0] as Record<string, unknown>
    : {};
  return {
    producer: typeof entry.producer === 'string' ? entry.producer : artifactOrigin(artifact),
    transformation: typeof entry.transformation === 'string' ? entry.transformation : 'Create a separate normalized recovery copy',
    reason: typeof entry.reason === 'string' ? entry.reason : 'The analyzer produced a bounded candidate that may restore a damaged structure.',
  };
}
function isRepairArtifact(artifact: Artifact) {
  if (artifact.kind === 'repair' || artifact.metadata?.repair_candidate === true) return true;
  if (artifact.kind === 'original') return false;
  const lineage = artifact.metadata?.lineage;
  const lineageText = Array.isArray(lineage)
    ? lineage.map((entry) => entry && typeof entry === 'object' ? Object.values(entry as Record<string, unknown>).join(' ') : '').join(' ')
    : '';
  return /\b(?:repair|normaliz|correct|fix|rebuild)\w*/i.test(`${artifactName(artifact)} ${artifact.origin || ''} ${artifact.method || ''} ${lineageText}`);
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
function formatHexByte(value: number) {
  return Math.max(0, Math.min(255, Math.floor(value))).toString(16).padStart(2, '0');
}
function hexRowBytes(row: HexRow) {
  if (Array.isArray(row.bytes)) return row.bytes;
  return row.hex.split(/\s+/).filter(Boolean).map((item) => Number.parseInt(item, 16)).filter((item) => Number.isFinite(item));
}
function integrityLabel(verdict?: HexIntegrity['verdict']) {
  if (verdict === 'valid') return 'Valid';
  if (verdict === 'warning') return 'Review warnings';
  if (verdict === 'corrupt') return 'Likely corrupt';
  return 'Unknown';
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
function SafePreviewImage({ src, alt, className, style }: { src: string; alt: string; className?: string; style?: CSSProperties }) {
  // These URLs are short-lived, locally generated forensic artifacts. Routing
  // them through an image optimizer would duplicate evidence bytes and break
  // the API's strict local-origin boundary.
  // eslint-disable-next-line @next/next/no-img-element
  return <img className={className} style={style} src={src} alt={alt} loading="lazy" decoding="async" />;
}
function HexByteCell({
  offset,
  value,
  original,
  highlighted,
  onChange,
  onBlur,
  onPaste,
  onContextMenu,
  onMouseEnter,
  onMouseLeave,
}: {
  offset: number;
  value: string;
  original: number;
  highlighted?: boolean;
  onChange: (value: string) => void;
  onBlur: (value: string) => void;
  onPaste: (event: ClipboardEvent<HTMLInputElement>) => void;
  onContextMenu: (event: ReactMouseEvent<HTMLInputElement>) => void;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
}) {
  const changed = value.length === 2 && Number.parseInt(value, 16) !== original;
  return <input
    className={`hex-byte-cell${changed ? ' changed' : ''}${highlighted ? ' hovered' : ''}`}
    value={value}
    inputMode="text"
    maxLength={2}
    spellCheck={false}
    aria-label={`Byte at ${formatHexOffset(offset)}, original ${original.toString(16).padStart(2, '0')}${changed ? `, edited ${value}` : ''}`}
    title={changed ? `Original ${original.toString(16).padStart(2, '0')} · edited ${value}` : `Original ${original.toString(16).padStart(2, '0')}`}
    onChange={(event) => onChange(event.target.value)}
    onBlur={(event) => onBlur(event.target.value)}
    onPaste={onPaste}
    onContextMenu={onContextMenu}
    onMouseEnter={onMouseEnter}
    onMouseLeave={onMouseLeave}
  />;
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
  const [uiPreferences, setUiPreferences] = useState<UiPreferences>(readUiPreferences);
  const [evidenceSection, setEvidenceSection] = useState<EvidenceSection>('image');
  const [screen, setScreen] = useState<Screen>('setup');
  const [profile, setProfile] = useState<Profile>('balanced');
  const [scanOptions, setScanOptions] = useState<ScanOptions>({ ...profileOptionDefaults.balanced, evidence_type: 'auto' });
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileDetection, setFileDetection] = useState<FileDetection | null>(null);
  const fileDetectionRequest = useRef(0);
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
  const [fullscreenVisual, setFullscreenVisual] = useState<VisualView | null>(null);
  const [fullscreenMode, setFullscreenMode] = useState<'fit' | 'fill' | 'pixel'>('fit');
  const [fullscreenZoom, setFullscreenZoom] = useState(1);
  const [fullscreenRotation, setFullscreenRotation] = useState(0);
  const [fullscreenScaleX, setFullscreenScaleX] = useState(1);
  const [fullscreenScaleY, setFullscreenScaleY] = useState(1);
  const [fullscreenSkewX, setFullscreenSkewX] = useState(0);
  const [fullscreenSkewY, setFullscreenSkewY] = useState(0);
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
  const [hexEdits, setHexEdits] = useState<Map<number, HexEdit>>(new Map());
  const [hexUndo, setHexUndo] = useState<HexEditAction[]>([]);
  const [hexRedo, setHexRedo] = useState<HexEditAction[]>([]);
  const [hexDraftBytes, setHexDraftBytes] = useState<Record<number, string>>({});
  const [hexEditPreview, setHexEditPreview] = useState<HexEditPreview | null>(null);
  const [hexPreviewUrl, setHexPreviewUrl] = useState('');
  const [hexPreviewBusy, setHexPreviewBusy] = useState(false);
  const [hexSaveBusy, setHexSaveBusy] = useState(false);
  const [hexRepairBusy, setHexRepairBusy] = useState(false);
  const [hexDerivedName, setHexDerivedName] = useState('');
  const [hexHoverOffset, setHexHoverOffset] = useState<number | null>(null);
  const [hexContextMenu, setHexContextMenu] = useState<HexContextMenu | null>(null);
  const hexRequestRef = useRef(0);
  const hexPreviewRequestRef = useRef(0);
  const hexPreviewUrlRef = useRef('');

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = uiPreferences.theme;
    root.style.setProperty('color-scheme', uiPreferences.theme);
    root.style.setProperty('zoom', String(uiPreferences.zoom / 100));
    try {
      window.localStorage.setItem(UI_PREFERENCES_KEY, JSON.stringify(uiPreferences));
    } catch { /* private browsing or storage policy can disable persistence */ }
  }, [uiPreferences]);

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

  useEffect(() => {
    if (!fullscreenVisual) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setFullscreenVisual(null);
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [fullscreenVisual]);

  useEffect(() => {
    if (!hexContextMenu) return;
    const closeMenu = (event: Event) => {
      const target = event.target;
      if (target instanceof Element && target.closest('[data-hex-context-menu]')) return;
      setHexContextMenu(null);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setHexContextMenu(null);
    };
    window.addEventListener('pointerdown', closeMenu);
    window.addEventListener('resize', closeMenu);
    window.addEventListener('scroll', closeMenu, true);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('pointerdown', closeMenu);
      window.removeEventListener('resize', closeMenu);
      window.removeEventListener('scroll', closeMenu, true);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [hexContextMenu]);

  useEffect(() => () => {
    if (hexPreviewUrlRef.current.startsWith('blob:')) URL.revokeObjectURL(hexPreviewUrlRef.current);
  }, []);

  const refreshJob = useCallback(async (id: string) => {
    if (!id) return;
    try {
      const next = await readJson(await fetch(`${API_BASE}/api/jobs/${id}`, { cache: 'no-store' })) as Job;
      setJob(next);
      if (next.profile) setProfile(next.profile);
      if (next.options) {
        setScanOptions({ ...profileOptionDefaults[next.profile || 'balanced'], ...next.options });
      }
      setEvidenceSection(sectionForJob(next));
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
  const sectionCopy = SECTION_COPY[evidenceSection];
  const setupCopy = {
    ...sectionCopy,
    symbol: '◈',
    setupEyebrow: 'Universal file forensics',
    headline: 'Drop any file. Find what it is hiding.',
    dropTitle: 'Drop any file here',
    formatCopy: 'Images, audio, archives, documents, captures, disk images and more',
    accept: '*/*',
    analyzeLabel: 'Analyze file',
    selectedNote: 'Type detected from content before the scan begins',
  };
  const currentConfigurableMethods = configurableMethodsFor(evidenceSection);
  const currentMethodGroups = methodGroupsFor(evidenceSection);
  const isAudioResult = result?.section === 'audio' || job?.options?.evidence_type === 'audio' || evidenceSection === 'audio';
  const isRecoveryResult = result?.section === 'corrupted' || job?.options?.evidence_type === 'corrupted' || evidenceSection === 'corrupted';
  const candidates = useMemo(() => getCandidates(result).slice().sort((a, b) => scoreOf(b) - scoreOf(a)), [result]);
  const artifacts = useMemo(() => job?.artifacts?.length ? job.artifacts : getArtifacts(result), [job, result]);
  const repairArtifacts = useMemo(() => artifacts.filter(isRepairArtifact), [artifacts]);
  const hexArtifactChoices = useMemo(() => artifacts.filter((artifact) => artifactId(artifact)), [artifacts]);
  const defaultHexArtifactId = artifactId(hexArtifactChoices.find((artifact) => artifact.kind === 'original') || hexArtifactChoices[0] || {});
  const effectiveHexArtifactId = hexArtifactChoices.some((artifact) => artifactId(artifact) === hexArtifactId) ? hexArtifactId : defaultHexArtifactId;
  const activeHexArtifact = useMemo(() => hexArtifactChoices.find((artifact) => artifactId(artifact) === effectiveHexArtifactId) || null, [effectiveHexArtifactId, hexArtifactChoices]);
  const baselineHexPreviewUrl = activeHexArtifact ? (artifactPreviewUrl(activeHexArtifact) || artifactAudioUrl(activeHexArtifact)) : '';
  const activeHexIntegrity = hexEditPreview?.integrity || hexView?.integrity;
  const hexRepairCandidates = activeHexIntegrity?.repair_candidates || [];
  const displayHexPreviewUrl = hexEdits.size ? hexPreviewUrl : baselineHexPreviewUrl;
  const replaceHexPreviewUrl = useCallback((next: string) => {
    const previous = hexPreviewUrlRef.current;
    if (previous && previous !== next && previous.startsWith('blob:')) URL.revokeObjectURL(previous);
    hexPreviewUrlRef.current = next;
    setHexPreviewUrl(next);
  }, []);
  const clearHexPreview = useCallback(() => {
    replaceHexPreviewUrl('');
    setHexEditPreview(null);
    setHexPreviewBusy(false);
  }, [replaceHexPreviewUrl]);
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
  useEffect(() => {
    const shouldPreview = activeTab === 'hex' && Boolean(activeJobId && activeHexArtifact && hexEdits.size);
    if (!shouldPreview || !activeJobId || !activeHexArtifact) {
      return;
    }
    const requestId = ++hexPreviewRequestRef.current;
    const controller = new AbortController();
    const editPayload = Array.from(hexEdits.values()).map((item) => ({ offset: item.offset, value: item.value }));
    const body = JSON.stringify({ artifact_id: artifactId(activeHexArtifact), base_sha256: String(activeHexArtifact.sha256 || '').toLowerCase(), revision: requestId, edits: editPayload });
    const timer = window.setTimeout(async () => {
      setHexPreviewBusy(true);
      try {
        const [analysisResponse, previewResponse] = await Promise.all([
          fetch(`${API_BASE}/api/jobs/${activeJobId}/hex/analyze`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, cache: 'no-store', signal: controller.signal }),
          fetch(`${API_BASE}/api/jobs/${activeJobId}/hex/preview`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body, cache: 'no-store', signal: controller.signal }),
        ]);
        const analysis = await readJson<HexEditPreview>(analysisResponse);
        if (requestId !== hexPreviewRequestRef.current) return;
        let nextUrl = '';
        let previewMessage = analysis.preview?.message || '';
        if (previewResponse.ok) {
          nextUrl = URL.createObjectURL(await previewResponse.blob());
        } else {
          try { await readJson(previewResponse); } catch (caught) { previewMessage = caught instanceof Error ? caught.message : previewMessage; }
        }
        replaceHexPreviewUrl(nextUrl);
        setHexEditPreview({ ...analysis, preview: { ...analysis.preview, url: nextUrl || undefined, message: previewMessage } });
        setHexError('');
      } catch (caught) {
        if (controller.signal.aborted || requestId !== hexPreviewRequestRef.current) return;
        setHexError(caught instanceof Error ? caught.message : 'The live edited preview could not be generated.');
      } finally {
        if (requestId === hexPreviewRequestRef.current) setHexPreviewBusy(false);
      }
    }, 320);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [activeHexArtifact, activeJobId, activeTab, hexEdits, replaceHexPreviewUrl]);
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
  const recoveryFindings = useMemo(() => findings.filter((finding) => ['identity', 'integrity', 'structure', 'repair', 'embedded-data', 'resource-limit'].includes((finding.category || '').toLowerCase())), [findings]);
  const damageFindings = useMemo(() => recoveryFindings.filter((finding) => (finding.category || '').toLowerCase() !== 'repair'), [recoveryFindings]);
  const recoveryMethods = useMemo(() => methods.filter((method) => ['identity', 'structure', 'repair', 'embedded-data'].includes((method.category || '').toLowerCase()) || ['built-in-core', 'built-in-structure', 'pcrt', 'jpegtran', 'binwalk', 'foremost', '7z'].includes(method.id || method.tool_id || '')), [methods]);
  const metadataRows = useMemo(() => flattenMetadata(Array.isArray(result?.metadata) ? result?.metadata[0] || {} : result?.metadata || {}), [result]);
  const normalizedQuery = resultQuery.trim().toLowerCase();
  const queryMatches = useCallback((...values: unknown[]) => !normalizedQuery || searchable(...values).includes(normalizedQuery), [normalizedQuery]);
  const filteredCandidates = candidates.filter((candidate) =>
    (candidateFilter === 'all' || confidenceBand(candidate) === candidateFilter)
    && queryMatches(candidateValue(candidate), candidateEvidence(candidate), candidate.reasons, candidate.occurrences, candidateTransformChain(candidate))
  );
  const filteredArtifacts = artifacts.filter((artifact) => queryMatches(artifactName(artifact), artifactMediaType(artifact), artifact.sha256, artifactOrigin(artifact), artifact.metadata));
  const filteredRepairArtifacts = repairArtifacts.filter((artifact) => queryMatches(artifactName(artifact), artifactMediaType(artifact), artifact.sha256, artifact.metadata, artifactRepairDetails(artifact)));
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
  const filteredRecoveryFindings = recoveryFindings.filter((finding) => queryMatches(finding.title, finding.description, finding.summary, finding.category, finding.method_id));
  const filteredVisuals = visuals.filter((view) => queryMatches(view.title, view.name, view.kind, view.category));
  const audioKinds = new Set(['audio', 'wav', 'aiff', 'flac', 'ogg', 'mp3', 'aac', 'm4a', 'au', 'asf', 'amr', 'caf', 'midi']);
  const imageKinds = new Set(['png', 'jpeg', 'gif', 'bmp', 'webp', 'tiff', 'ico']);
  const relevantCapabilities = capabilities.filter((capability) => {
    if (evidenceSection === 'corrupted') return true;
    const formats = capability.formats || ['all'];
    if (formats.includes('all')) return true;
    return formats.some((format) => (evidenceSection === 'audio' ? audioKinds : imageKinds).has(format.toLowerCase()));
  });
  const webRepairCapabilities = relevantCapabilities.filter((capability) => capability.category === 'repair' && capability.source_url);
  const availableTools = relevantCapabilities.filter((capability) => capability.available === true).length;
  const armedMethodCount = 1 + currentConfigurableMethods.filter((method) => scanOptions[method.key]).length + availableTools;
  const activeResultTabs = resultTabs.filter((tab) => {
    if (tab.id === 'audio') return isAudioResult;
    if (tab.id === 'repairs') return isRecoveryResult || repairArtifacts.length > 0;
    return true;
  });
  const originalArtifact = artifacts.find((artifact) => artifact.kind === 'original');
  const recoveredArtifacts = artifacts.filter((artifact) => artifact.kind !== 'original' && !isRepairArtifact(artifact));
  const sourceDetails = result?.source;
  const audioProperties = result?.audio_analysis?.metadata?.properties || {};
  const audioStatistics = result?.audio_analysis?.metadata?.statistics || {};
  const audioSignals = result?.audio_analysis?.signals || {};
  const audioVisuals = visuals.filter((view) => String(view.category || '').startsWith('audio-'));
  const sstvVisuals = audioVisuals.filter((view) => view.category === 'audio-sstv-image');
  const diagnosticAudioVisuals = audioVisuals.filter((view) => view.category !== 'audio-sstv-image');
  const audioArtifacts = artifacts.filter((artifact) => Boolean(artifactAudioUrl(artifact)));
  const primaryAudioArtifact = audioArtifacts.find((artifact) => artifact.kind === 'original') || audioArtifacts.find((artifact) => artifactName(artifact).includes('audacity_review_normalized')) || audioArtifacts[0];

  function selectFile(file?: File | null) {
    setError('');
    if (!file) return;
    if (file.size > 100 * 1024 * 1024) { setError('That file is larger than the 100 MB safety limit.'); return; }
    setSelectedFile(file);
    const request = ++fileDetectionRequest.current;
    setFileDetection({ label: 'Inspecting file signature…', source: 'scanning' });
    void detectClientFileType(file).then((detected) => {
      if (request === fileDetectionRequest.current) setFileDetection(detected);
    }).catch(() => {
      if (request === fileDetectionRequest.current) setFileDetection({ label: 'Type will be detected by the analysis engine', source: 'scanning' });
    });
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
    form.append('options', JSON.stringify({ ...scanOptions, evidence_type: 'auto' }));
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

  function originalHexByteAt(offset: number) {
    const row = hexView?.rows.find((candidate) => offset >= candidate.offset && offset < candidate.offset + candidate.length);
    if (!row) return undefined;
    return hexRowBytes(row)[offset - row.offset];
  }

  function applyHexActionToMap(current: Map<number, HexEdit>, action: HexEditAction, direction: 'undo' | 'redo') {
    const next = new Map(current);
    for (const item of action) {
      const value = direction === 'undo' ? item.before : item.after;
      if (value === item.original) next.delete(item.offset);
      else next.set(item.offset, { offset: item.offset, original: item.original, value });
    }
    return next;
  }

  function applyHexAction(action: HexEditAction) {
    if (!action.length) return false;
    setHexEdits((current) => applyHexActionToMap(current, action, 'redo'));
    setHexUndo((current) => [...current, action]);
    setHexRedo([]);
    setHexDraftBytes({});
    setHexError('');
    return true;
  }

  function openHexContextMenu(event: ReactMouseEvent<HTMLInputElement>, offset: number) {
    event.preventDefault();
    event.stopPropagation();
    const row = hexView?.rows.find((candidate) => offset >= candidate.offset && offset < candidate.offset + candidate.length);
    const original = originalHexByteAt(offset);
    if (!row || original === undefined) return;
    const current = hexEdits.get(offset)?.value ?? original;
    const menuWidth = 248;
    const menuHeight = 238;
    setHexHoverOffset(offset);
    setHexContextMenu({
      x: Math.max(8, Math.min(event.clientX, Math.max(8, window.innerWidth - menuWidth - 8))),
      y: Math.max(8, Math.min(event.clientY, Math.max(8, window.innerHeight - menuHeight - 8))),
      offset,
      original,
      value: current,
      blockStart: row.offset,
      blockLength: row.length,
    });
  }

  function restoreHexByte(offset: number) {
    const existing = hexEdits.get(offset);
    if (!existing) {
      setHexContextMenu(null);
      return;
    }
    applyHexAction([{ offset, original: existing.original, before: existing.value, after: existing.original }]);
    setHexContextMenu(null);
  }

  function deleteHexUnit(offset: number) {
    const original = originalHexByteAt(offset);
    if (original === undefined) {
      setHexError('The byte is no longer visible. Scroll it into view and try again.');
      setHexContextMenu(null);
      return;
    }
    const before = hexEdits.get(offset)?.value ?? original;
    if (before === 0) {
      setHexError('This byte is already 00.');
      setHexContextMenu(null);
      return;
    }
    applyHexAction([{ offset, original, before, after: 0 }]);
    setHexContextMenu(null);
  }

  function deleteHexBlock(blockStart: number, blockLength: number) {
    const row = hexView?.rows.find((candidate) => candidate.offset === blockStart);
    if (!row) {
      setHexError('The byte block is no longer visible. Scroll it into view and try again.');
      setHexContextMenu(null);
      return;
    }
    const action: HexEditAction = [];
    for (const [index, original] of hexRowBytes(row).entries()) {
      if (index >= blockLength) break;
      const offset = blockStart + index;
      const before = hexEdits.get(offset)?.value ?? original;
      if (before !== 0) action.push({ offset, original, before, after: 0 });
    }
    if (!applyHexAction(action)) setHexError('This block is already filled with 00 bytes.');
    setHexContextMenu(null);
  }

  function commitHexByte(offset: number, nextValue: number) {
    if (!Number.isInteger(nextValue) || nextValue < 0 || nextValue > 255) return;
    const existing = hexEdits.get(offset);
    const original = existing?.original ?? originalHexByteAt(offset);
    if (original === undefined) {
      setHexError('Scroll the byte into view before editing it so its original value can be verified.');
      return;
    }
    const before = existing?.value ?? original;
    if (before === nextValue) {
      setHexDraftBytes((current) => { const next = { ...current }; delete next[offset]; return next; });
      return;
    }
    const action: HexEditAction = [{ offset, original, before, after: nextValue }];
    setHexEdits((current) => applyHexActionToMap(current, action, 'redo'));
    setHexUndo((current) => [...current, action]);
    setHexRedo([]);
    setHexDraftBytes((current) => { const next = { ...current }; delete next[offset]; return next; });
    setHexError('');
  }

  function handleHexByteDraft(offset: number, raw: string) {
    const value = raw.replace(/[^0-9a-f]/gi, '').slice(0, 2).toLowerCase();
    setHexDraftBytes((current) => ({ ...current, [offset]: value }));
    if (value.length === 2) commitHexByte(offset, Number.parseInt(value, 16));
  }

  function finishHexByteDraft(offset: number, raw: string) {
    const value = raw.replace(/[^0-9a-f]/gi, '').slice(0, 2).toLowerCase();
    if (!value) {
      setHexDraftBytes((current) => { const next = { ...current }; delete next[offset]; return next; });
      return;
    }
    commitHexByte(offset, Number.parseInt(value.padStart(2, '0'), 16));
  }

  function pasteHexBytes(startOffset: number, raw: string) {
    const compact = raw.replace(/[\s:_-]/g, '').toLowerCase();
    if (!compact || compact.length % 2 || !/^[0-9a-f]+$/.test(compact)) {
      setHexError('Paste an even number of hexadecimal digits, optionally separated by spaces.');
      return;
    }
    const action: HexEditAction = [];
    const next = new Map(hexEdits);
    for (let index = 0; index < compact.length; index += 2) {
      const offset = startOffset + index / 2;
      const original = next.get(offset)?.original ?? originalHexByteAt(offset);
      if (original === undefined) break;
      const after = Number.parseInt(compact.slice(index, index + 2), 16);
      const before = next.get(offset)?.value ?? original;
      if (before === after) continue;
      action.push({ offset, original, before, after });
      if (after === original) next.delete(offset);
      else next.set(offset, { offset, original, value: after });
    }
    if (!action.length) {
      setHexError('The pasted bytes made no changes in the visible byte window.');
      return;
    }
    setHexEdits(next);
    setHexUndo((current) => [...current, action]);
    setHexRedo([]);
    setHexDraftBytes({});
    setHexError('');
  }

  function undoHexEdit() {
    const action = hexUndo[hexUndo.length - 1];
    if (!action) return;
    setHexEdits((current) => applyHexActionToMap(current, action, 'undo'));
    setHexUndo((current) => current.slice(0, -1));
    setHexRedo((current) => [...current, action]);
    setHexDraftBytes({});
  }

  function redoHexEdit() {
    const action = hexRedo[hexRedo.length - 1];
    if (!action) return;
    setHexEdits((current) => applyHexActionToMap(current, action, 'redo'));
    setHexRedo((current) => current.slice(0, -1));
    setHexUndo((current) => [...current, action]);
    setHexDraftBytes({});
  }

  function discardHexEdits() {
    hexPreviewRequestRef.current += 1;
    setHexEdits(new Map());
    setHexUndo([]);
    setHexRedo([]);
    setHexDraftBytes({});
    setHexHoverOffset(null);
    setHexContextMenu(null);
    clearHexPreview();
    setHexError('');
  }

  function handleHexEditorKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (!(event.ctrlKey || event.metaKey)) return;
    if (event.key.toLowerCase() === 'z' && event.shiftKey) {
      event.preventDefault();
      redoHexEdit();
    } else if (event.key.toLowerCase() === 'z') {
      event.preventDefault();
      undoHexEdit();
    } else if (event.key.toLowerCase() === 's') {
      event.preventDefault();
      void saveHexEdits();
    }
  }

  async function saveHexEdits() {
    if (!activeJobId || !activeHexArtifact || !hexEdits.size || hexSaveBusy) return;
    setHexSaveBusy(true);
    setHexError('');
    try {
      const response = await fetch(`${API_BASE}/api/jobs/${activeJobId}/hex/save`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          artifact_id: artifactId(activeHexArtifact),
          base_sha256: String(activeHexArtifact.sha256 || '').toLowerCase(),
          revision: hexPreviewRequestRef.current,
          name: hexDerivedName.trim() || undefined,
          edits: Array.from(hexEdits.values()).map((item) => ({ offset: item.offset, value: item.value })),
        }),
      });
      const saved = await readJson<{ artifact?: Artifact }>(response);
      const derived = saved.artifact;
      if (!derived) throw new Error('The server did not return the saved artifact.');
      discardHexEdits();
      setHexArtifactId(artifactId(derived));
      setHexView(null);
      await refreshJob(activeJobId);
    } catch (caught) {
      setHexError(caught instanceof Error ? caught.message : 'The edited artifact could not be saved.');
    } finally {
      setHexSaveBusy(false);
    }
  }

  async function saveHexRepair(candidate: HexRepairCandidate) {
    if (!activeJobId || !activeHexArtifact || hexRepairBusy) return;
    if (hexEdits.size) {
      setHexError('Save or discard the unsaved byte edits before creating a source repair candidate.');
      return;
    }
    setHexRepairBusy(true);
    setHexError('');
    try {
      const response = await fetch(`${API_BASE}/api/jobs/${activeJobId}/hex/repair`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          artifact_id: artifactId(activeHexArtifact),
          base_sha256: String(activeHexArtifact.sha256 || '').toLowerCase(),
          candidate_id: candidate.id,
        }),
      });
      const saved = await readJson<{ artifact?: Artifact }>(response);
      const derived = saved.artifact;
      if (!derived) throw new Error('The server did not return the repair artifact.');
      setHexArtifactId(artifactId(derived));
      setHexView(null);
      await refreshJob(activeJobId);
    } catch (caught) {
      setHexError(caught instanceof Error ? caught.message : 'The repair candidate could not be saved.');
    } finally {
      setHexRepairBusy(false);
    }
  }

  function resetScan() {
    setScreen('setup');
    setEvidenceSection('image');
    setSelectedFile(null);
    setFileDetection(null);
    fileDetectionRequest.current += 1;
    if (fileInput.current) fileInput.current.value = '';
    setScanOptions((current) => ({ ...current, evidence_type: 'auto' }));
    setJob(null);
    setError('');
    setActivity([]);
    setActiveTab('overview');
    setSelectedVisual(null);
    setFullscreenVisual(null);
    setSelectedArtifact(null);
    setHexArtifactId('');
    setHexOffset(0);
    setHexOffsetInput('0');
    setHexSearchInput('');
    setHexSearch('');
    setHexView(null);
    setHexError('');
    discardHexEdits();
    setHexDerivedName('');
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
    setFullscreenVisual(null);
    setSelectedArtifact(null);
    setHexView(null);
    setHexError('');
    discardHexEdits();
    setHexDerivedName('');
    setResultQuery('');
    setToolInstallReport(null);
    setScanOptions({ ...profileOptionDefaults[profile], evidence_type: next });
  }

  function openFullscreenVisual(view: VisualView) {
    if (!view.preview_url) return;
    setFullscreenMode('fit');
    setFullscreenZoom(1);
    setFullscreenRotation(0);
    setFullscreenScaleX(1);
    setFullscreenScaleY(1);
    setFullscreenSkewX(0);
    setFullscreenSkewY(0);
    setFullscreenVisual(view);
  }

  function resetFullscreenTransform() {
    setFullscreenZoom(1);
    setFullscreenRotation(0);
    setFullscreenScaleX(1);
    setFullscreenScaleY(1);
    setFullscreenSkewX(0);
    setFullscreenSkewY(0);
  }

  function selectHexArtifact(value: string) {
    if (hexEdits.size && typeof window !== 'undefined' && !window.confirm('Discard the unsaved byte edits and switch artifacts?')) return;
    discardHexEdits();
    setHexArtifactId(value);
    setHexOffset(0);
    setHexOffsetInput('0');
    setHexSearchInput('');
    setHexSearch('');
    setHexView(null);
    setHexError('');
    const selected = hexArtifactChoices.find((artifact) => artifactId(artifact) === value);
    const baseName = selected ? artifactName(selected) : '';
    setHexDerivedName(baseName ? `${baseName.replace(/\.[^.]+$/, '')}-edited${baseName.match(/\.[^.]+$/)?.[0] || '.bin'}` : '');
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
      audio_sstv_max_images: defaults.audio_sstv_max_images,
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
    if (hexEdits.size && typeof window !== 'undefined' && !window.confirm('Discard the unsaved byte edits and open another scan?')) return;
    discardHexEdits();
    setHexView(null);
    setHexArtifactId('');
    setJob(recent);
    setActiveTab('overview');
    if (recent.profile) setProfile(recent.profile);
    if (recent.options) setScanOptions({ ...profileOptionDefaults[recent.profile || 'balanced'], ...recent.options });
    setEvidenceSection(sectionForJob(recent));
    const id = getJobId(recent);
    if (id) await refreshJob(id);
    setScreen(TERMINAL.has(recent.status.toLowerCase()) ? 'results' : 'running');
  }

  const jobId = activeJobId;
  const rawProgress = Number(job?.progress || 0);
  const progress = Math.max(0, Math.min(100, rawProgress > 0 && rawProgress <= 1 ? rawProgress * 100 : rawProgress));
  const currentStage = job?.current_stage || job?.stage || job?.message || 'Preparing analyzers';
  const successfulMethods = methods.filter((method) => ['completed', 'success', 'succeeded', 'no_findings'].includes((method.status || '').toLowerCase())).length;
  const hexPreviewKind: 'image' | 'audio' | 'none' = hexEditPreview?.preview.kind || (activeHexArtifact && artifactPreviewUrl(activeHexArtifact) ? 'image' : activeHexArtifact && artifactAudioUrl(activeHexArtifact) ? 'audio' : 'none');

  return (
    <main className={`app-shell theme-${uiPreferences.theme}`} data-interface-zoom={uiPreferences.zoom}>
      <aside className="sidebar">
        <button className="brand brand-button" onClick={resetScan} aria-label="Return to new scan">
          <span className="brand-mark" aria-hidden="true">F</span>
          <span><strong>Forenscope</strong><small>CTF workbench</small></span>
        </button>

        <nav aria-label="Forensics workspace">
          <button className="nav-item active universal-nav-item" onClick={resetScan}><span>◈</span>New analysis</button>
          <p className="nav-label second">Workspace</p>
          <button className="nav-item" onClick={() => document.getElementById('recent-scans')?.scrollIntoView({ behavior: 'smooth' })}><span>◷</span>Recent scans</button>
          <button className="nav-item" onClick={() => setShowAdvanced(true)}><span>⌘</span>Scan settings</button>
        </nav>

        <div className="recent-mini" id="recent-scans">
          {recentJobs.slice(0, 3).map((recent) => (
            <button key={getJobId(recent)} onClick={() => openRecent(recent)}>
              <span className={`mini-status ${recent.status}`} />
              <span><strong>{jobName(recent) || SECTION_COPY[sectionForJob(recent)].fallbackName}</strong><small>{recent.status}</small></span>
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

      <section className={`workspace screen-${screen} mode-${evidenceSection}`}>
        {screen === 'setup' && (
          <>
            <header className="topbar">
              <div><p className="eyebrow">{setupCopy.setupEyebrow}</p><h1>{setupCopy.headline}</h1></div>
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
                  <input ref={fileInput} className="sr-only" type="file" accept={setupCopy.accept} onChange={(event) => selectFile(event.target.files?.[0])} />
                  {!selectedFile ? (
                    <>
                      <div className="upload-icon" aria-hidden="true"><span>↑</span></div>
                      <p className="card-kicker">Start an investigation</p>
                      <h2>{setupCopy.dropTitle}</h2>
                      <p className="upload-copy">{setupCopy.formatCopy} · up to 100 MB</p>
                      <button className="choose-button" onClick={(event) => { event.stopPropagation(); fileInput.current?.click(); }}>Choose a file</button>
                      <p className="evidence-note"><span>◇</span>Content signatures detect the real type, even when the extension is missing or wrong</p>
                    </>
                  ) : (
                    <>
                      <div className="file-seal" aria-hidden="true"><span>{setupCopy.symbol}</span><i>Evidence</i></div>
                      <p className="card-kicker">Evidence selected</p>
                      <h2 className="file-name">{selectedFile.name}</h2>
                      <div className="file-facts"><span>{formatBytes(selectedFile.size)}</span><span>SHA-256 on ingest</span><span className={`file-type-fact ${fileDetection?.source === 'scanning' ? 'scanning' : ''}`}>{fileDetection?.label || 'Detecting type…'}</span></div>
                      <p className="file-detection-note">{fileDetection?.source === 'content' ? 'Detected from the file signature' : fileDetection?.source === 'extension' ? 'Detected from the filename extension; the engine will verify it' : fileDetection?.source === 'browser' ? 'Browser MIME hint; the engine will verify it' : 'Reading the first bytes to identify the format…'}</p>
                      <div className="file-actions">
                        <button className="choose-button" onClick={(event) => { event.stopPropagation(); startScan(); }}>{setupCopy.analyzeLabel} <span>→</span></button>
                        <button className="replace-button" onClick={(event) => { event.stopPropagation(); fileInput.current?.click(); }}>Replace</button>
                      </div>
                      <p className="evidence-note"><span>◇</span>{setupCopy.selectedNote}</p>
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
                  {showPassword && <><input className="password-input" type="password" value={password} autoComplete="off" onChange={(event) => setPassword(event.target.value.slice(0, 256))} placeholder="Optional recovery or decryption passphrase" /><small className="password-hint">Used only for this scan. {sectionCopy.passwordHint} Prefix a raw key with <code>hex:</code>.</small></>}
                </div>
                {recentJobs.length > 0 && (
                  <section className="mobile-recent-scans" aria-labelledby="mobile-recent-title">
                    <div><p className="eyebrow">Workspace</p><h2 id="mobile-recent-title">Recent investigations</h2></div>
                    <div>
                      {recentJobs.slice(0, 5).map((recent) => (
                        <button key={getJobId(recent)} onClick={() => openRecent(recent)}>
                          <span className={`mini-status ${recent.status}`} />
                          <span><strong>{jobName(recent) || SECTION_COPY[sectionForJob(recent)].fallbackName}</strong><small>{formatDate(recent.updated_at)}</small></span>
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
                  {currentMethodGroups.map((method, index) => (
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
                  {showPassword && <><input className="password-input" type="password" value={password} autoComplete="off" onChange={(event) => setPassword(event.target.value.slice(0, 256))} placeholder="Optional recovery or decryption passphrase" /><small className="password-hint">Used only for this scan. {sectionCopy.passwordHint} Prefix a raw key with <code>hex:</code>.</small></>}
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
              <div><p className="eyebrow">{isRecoveryResult ? 'Live recovery' : 'Live investigation'}</p><h1>{isRecoveryResult ? 'Diagnosing' : 'Interrogating'} <span>{jobName(job) || selectedFile?.name || 'evidence'}</span></h1></div>
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
                <p className="stage-copy">{isRecoveryResult ? 'Signatures, container boundaries and repair candidates are checked against an isolated working copy. The source is never overwritten.' : 'Every parser runs against an isolated per-job working copy. Results appear as soon as they are validated.'}</p>
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
                <div><p className="eyebrow">{isRecoveryResult ? SECTION_COPY.corrupted.resultEyebrow : isAudioResult ? SECTION_COPY.audio.resultEyebrow : SECTION_COPY.image.resultEyebrow}</p><h1>{jobName(job) || selectedFile?.name || sectionCopy.fallbackName}</h1></div>
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

            {isRecoveryResult ? (
              <section className={`repair-hero ${repairArtifacts.length ? 'ready' : 'review'}`}>
                <div className="repair-hero-mark"><span>{repairArtifacts.length ? '✓' : '⌁'}</span></div>
                <div>
                  <p>{repairArtifacts.length ? 'Safe recovery output' : 'Diagnosis complete'}</p>
                  <strong>{repairArtifacts.length ? `${repairArtifacts.length} repair candidate${repairArtifacts.length === 1 ? '' : 's'} ready` : 'No deterministic repair was generated'}</strong>
                  <small>{repairArtifacts.length ? 'Every candidate is a separate hashed copy; the original evidence remains untouched.' : `${damageFindings.length} structural signal${damageFindings.length === 1 ? '' : 's'} recorded. Carved files, raw bytes and tool output remain available.`}</small>
                </div>
                <button onClick={() => setActiveTab('repairs')}>{repairArtifacts.length ? 'Review repairs' : 'Open diagnosis'} <span>→</span></button>
              </section>
            ) : candidates.length > 0 ? (
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
              {activeResultTabs.map((tab) => <button key={tab.id} className={activeTab === tab.id ? 'active' : ''} onClick={() => setActiveTab(tab.id)}>{tab.label}{tab.id === 'repairs' && <span>{repairArtifacts.length}</span>}{tab.id === 'audio' && <span>{audioVisuals.length}</span>}{tab.id === 'candidates' && <span>{candidates.length}</span>}{tab.id === 'artifacts' && <span>{artifacts.length}</span>}{tab.id === 'metadata' && <span>{metadataRows.length}</span>}{tab.id === 'tools' && <span>{toolMethods.length}</span>}{tab.id === 'methods' && <span>{methods.length}</span>}</button>)}
            </nav>

            <div className="result-search">
              <span aria-hidden="true">⌕</span>
              <label className="sr-only" htmlFor="evidence-search">Search all recovered information</label>
              <input id="evidence-search" type="search" value={resultQuery} onChange={(event) => setResultQuery(event.target.value)} placeholder={isRecoveryResult ? 'Search damage signals, repairs, hashes, artifacts and tool output…' : 'Search flags, metadata, hashes, artifacts and tool output…'} />
              {resultQuery && <button onClick={() => setResultQuery('')} aria-label="Clear evidence search">Clear</button>}
              <small>{resultQuery ? `${filteredCandidates.length + filteredArtifacts.length + filteredToolMethods.length + filteredMetadata.length} matching records` : `${candidates.length + artifacts.length + toolMethods.length + metadataRows.length} indexed records`}</small>
            </div>

            <div className="result-content">
              {activeTab === 'overview' && (
                <div className="overview-grid">
                  <section className="metric-grid">
                    {isRecoveryResult ? <>
                      <div className="metric-card green"><span>✓</span><strong>{repairArtifacts.length}</strong><p>Repair candidates</p><small>Separate, hashed copies</small></div>
                      <div className="metric-card blue"><span>⌁</span><strong>{recoveredArtifacts.length}</strong><p>Recovered files</p><small>Carved lineage preserved</small></div>
                      <div className="metric-card purple"><span>⌘</span><strong>{successfulMethods || methods.length}</strong><p>Methods completed</p><small>{recoveryMethods.length} recovery-focused checks</small></div>
                      <div className="metric-card amber"><span>!</span><strong>{damageFindings.length}</strong><p>Integrity signals</p><small>{sourceDetails?.extension_matches_content === false ? 'Type mismatch included' : 'Structure and identity review'}</small></div>
                    </> : <>
                      <div className="metric-card green"><span>✦</span><strong>{candidates.length}</strong><p>Flag candidates</p><small>{candidates.filter((item) => confidenceBand(item) === 'high').length} high confidence</small></div>
                      <div className="metric-card blue"><span>⌁</span><strong>{artifacts.length}</strong><p>Recovered artifacts</p><small>All lineage preserved</small></div>
                      <div className="metric-card purple"><span>⌘</span><strong>{successfulMethods || methods.length}</strong><p>Methods completed</p><small>{methods.filter((item) => ['failed', 'timeout', 'tool_error'].includes((item.status || '').toLowerCase())).length} limited or failed</small></div>
                      <div className="metric-card amber"><span>◫</span><strong>{visuals.length}</strong><p>Visual derivatives</p><small>Safe PNG previews</small></div>
                    </>}
                  </section>
                  <section className="findings-panel">
                    <div className="section-title"><div><p className="eyebrow">{isRecoveryResult ? 'Damage & recovery signals' : 'Notable evidence'}</p><h2>{isRecoveryResult ? 'What the diagnosis found' : 'What deserves attention'}</h2></div><span>{findings.length} findings</span></div>
                    <div className="finding-list">
                      {filteredFindings.slice(0, 8).map((finding, index) => (
                        <article key={finding.id || `${finding.title}-${index}`}>
                          <span className="finding-index">{String(index + 1).padStart(2, '0')}</span>
                          <div><strong>{finding.title || finding.category || 'Forensic finding'}</strong><p>{finding.description || finding.summary || finding.evidence || 'Evidence recorded by the analysis engine.'}</p><small>{finding.method_id || finding.method || finding.category}{finding.offset !== undefined ? ` · offset 0x${finding.offset.toString(16)}` : ''}</small></div>
                        </article>
                      ))}
                      {!filteredFindings.length && <div className="empty-state"><span>✓</span><strong>{resultQuery ? 'No findings match this search' : 'No structural warnings were reported'}</strong><p>{isRecoveryResult ? 'The file may already be structurally sound; inspect Hex view when challenge context suggests otherwise.' : 'Review method coverage for skipped or unavailable tools.'}</p></div>}
                    </div>
                  </section>
                </div>
              )}

              {activeTab === 'repairs' && (
                <section className="tab-panel repair-lab-panel">
                  <div className="section-title"><div><p className="eyebrow">Non-destructive recovery</p><h2>Repair laboratory</h2></div><span>{repairArtifacts.length} candidate{repairArtifacts.length === 1 ? '' : 's'} · source preserved</span></div>
                  <p className="panel-lede">Forenscope records only bounded, derived copies. Download a candidate for review; it never replaces the uploaded evidence or changes its original hash.</p>

                  <section className={`repair-verdict ${repairArtifacts.length ? 'recoverable' : damageFindings.length ? 'attention' : 'clean'}`}>
                    <span>{repairArtifacts.length ? '✓' : damageFindings.length ? '!' : '◇'}</span>
                    <div><p>{repairArtifacts.length ? 'Safe candidate available' : damageFindings.length ? 'Manual review recommended' : 'No automatic repair needed'}</p><h3>{repairArtifacts.length ? `${repairArtifacts.length} copy-only repair${repairArtifacts.length === 1 ? '' : 's'} generated` : damageFindings.length ? 'Damage signals were found, but no deterministic fix was safe to write' : 'No format-level fault required a deterministic repair'}</h3><small>{sourceDetails?.extension_matches_content === false ? 'The filename extension and detected bytes disagree; treat the content signature as authoritative.' : 'Original bytes remain immutable throughout diagnosis and recovery.'}</small></div>
                    <strong>{formatBytes(sourceDetails?.size ?? artifactSize(originalArtifact || {}))}<small>source bytes preserved</small></strong>
                  </section>

                  <div className="repair-stat-grid">
                    <div><strong>{sourceDetails?.detected_type || artifactMediaType(originalArtifact || {})}</strong><small>detected type</small></div>
                    <div><strong>{damageFindings.length}</strong><small>integrity signals</small></div>
                    <div><strong>{recoveredArtifacts.length}</strong><small>carved files</small></div>
                    <div><strong>{recoveryMethods.filter((method) => methodStatusGroup(method) === 'completed').length}</strong><small>recovery checks</small></div>
                  </div>

                  <section className="repair-candidate-section">
                    <div className="repair-subheading"><div><p className="eyebrow">Derived evidence</p><h3>Repair candidates</h3></div><span>Download only · never in-place</span></div>
                    <div className="repair-candidate-list">
                      {filteredRepairArtifacts.map((artifact, index) => {
                        const details = artifactRepairDetails(artifact);
                        const id = artifactId(artifact);
                        const download = normalizeUrl(artifact.download_url) || `${API_BASE}/api/jobs/${jobId}/artifacts/${id}/download`;
                        return <article key={id || `${artifactName(artifact)}-${index}`}>
                          <header><span>{String(index + 1).padStart(2, '0')}</span><div><strong>{artifactName(artifact)}</strong><small>{artifactMediaType(artifact)} · {formatBytes(artifactSize(artifact))} · {details.producer}</small></div><em>Separate copy</em></header>
                          <p>{details.reason}</p>
                          <dl><div><dt>Transformation</dt><dd>{details.transformation}</dd></div><div><dt>Candidate SHA-256</dt><dd className="mono">{artifact.sha256 || 'Unavailable'}</dd></div></dl>
                          <footer><span>Source hash remains {String(sourceDetails?.sha256 || job?.sha256 || 'preserved').slice(0, 16)}{sourceDetails?.sha256 || job?.sha256 ? '…' : ''}</span><a href={download} download>Download candidate ↓</a></footer>
                        </article>;
                      })}
                      {!filteredRepairArtifacts.length && <div className="empty-state large"><span>⌁</span><strong>{resultQuery ? 'No repair candidates match this search' : 'No safe automatic repair was found'}</strong><p>{resultQuery ? 'Clear the search to see every recorded recovery copy.' : 'Review the structural signals, then inspect the source in Hex view or carved files in Artifacts.'}</p></div>}
                    </div>
                  </section>

                  <div className="repair-lab-grid">
                    <section className="repair-findings-panel">
                      <div className="repair-subheading"><div><p className="eyebrow">Diagnosis record</p><h3>Structural signals</h3></div><span>{recoveryFindings.length}</span></div>
                      <div className="repair-finding-list">
                        {filteredRecoveryFindings.slice(0, 10).map((finding, index) => <article key={finding.id || `${finding.title}-${index}`}><span className={finding.severity || 'info'}>{finding.severity === 'warning' ? '!' : finding.severity === 'error' ? '×' : 'i'}</span><div><strong>{finding.title || finding.category || 'Recovery signal'}</strong><p>{finding.description || finding.summary || finding.evidence || 'Evidence recorded by the analysis engine.'}</p><small>{finding.method_id || finding.method || finding.category}{finding.offset !== undefined ? ` · ${formatHexOffset(finding.offset)}` : ''}</small></div></article>)}
                        {!filteredRecoveryFindings.length && <div className="empty-state"><span>✓</span><strong>{resultQuery ? 'No diagnosis signals match this search' : 'No structural signals were reported'}</strong><p>The initial integrity checks did not identify a repairable boundary or checksum fault.</p></div>}
                      </div>
                    </section>
                    <aside className="repair-next-steps">
                      <p className="eyebrow">Evidence-safe next steps</p>
                      <h3>Keep the source, test the copy.</h3>
                      <p>Candidate files are isolated artifacts with their own hashes and lineage. Compare them against the original before using either in a challenge workflow.</p>
                      <dl><div><dt>Original SHA-256</dt><dd className="mono">{sourceDetails?.sha256 || job?.sha256 || 'Unavailable'}</dd></div><div><dt>Inspection</dt><dd>{sourceDetails?.inspection_truncated ? 'Bounded prefix; full file hashed' : 'Complete source read when profile allowed'}</dd></div></dl>
                      <div><button onClick={() => setActiveTab('hex')}>Inspect source bytes</button><button onClick={() => setActiveTab('artifacts')}>Browse recovered files</button><button onClick={() => setActiveTab('tools')}>Review tool output</button></div>
                    </aside>
                  </div>
                </section>
              )}

              {activeTab === 'audio' && isAudioResult && (
                <section className="tab-panel audio-lab-panel">
                  <div className="section-title"><div><p className="eyebrow">Signal workstation</p><h2>Audio laboratory</h2></div><span>{audioVisuals.length} visual analyses · {audioArtifacts.length} playable files</span></div>
                  <p className="panel-lede">Listen to content-verified local audio, compare waveform and spectral evidence, inspect decoded tones, and download channel or Audacity review exports without changing the source.</p>
                  <div className="audio-player-card">
                    <div><span className="audio-player-mark">≋</span><div><strong>{primaryAudioArtifact ? artifactName(primaryAudioArtifact) : 'No browser-playable artifact'}</strong><small>{primaryAudioArtifact ? `${artifactMediaType(primaryAudioArtifact)} · ${formatBytes(artifactSize(primaryAudioArtifact))}` : 'Install FFmpeg to create a PCM review WAV for this format.'}</small></div></div>
                    {primaryAudioArtifact && artifactAudioUrl(primaryAudioArtifact) ? <audio controls preload="metadata" src={artifactAudioUrl(primaryAudioArtifact)}>Your browser cannot play this verified audio artifact.</audio> : <p>Playback is unavailable, but waveform, metadata, carving, and raw-tool evidence remain accessible.</p>}
                  </div>
                  <section className={`sstv-recovery-panel ${sstvVisuals.length ? 'decoded' : ''}`}>
                    <div className="audio-subheading"><div><p className="eyebrow">RX-SSTV image recovery</p><h3>{sstvVisuals.length ? `${sstvVisuals.length} image${sstvVisuals.length === 1 ? '' : 's'} decoded from audio` : 'No decoded SSTV image'}</h3></div><span>{audioSignals.sstv?.requested_mode || 'Auto (VIS)'}</span></div>
                    {sstvVisuals.length ? <div className="sstv-recovery-grid">{sstvVisuals.map((view, index) => {
                      const preview = normalizeUrl(view.preview_url) || (view.artifact_id ? `${API_BASE}/api/jobs/${jobId}/artifacts/${view.artifact_id}/preview` : '');
                      return <button key={view.id || index} title="Double-click to open this image full screen" onDoubleClick={() => openFullscreenVisual({ ...view, preview_url: preview })} onClick={() => { setSelectedVisual({ ...view, preview_url: preview }); setActiveTab('visual'); }}><SafePreviewImage src={preview} alt={view.title || `Recovered SSTV image ${index + 1}`} /><span><strong>{view.title || `Recovered SSTV image ${index + 1}`}</strong><small>{String(view.parameters?.decoded_rows || view.height || '—')}/{String(view.parameters?.expected_rows || view.height || '—')} rows · {view.parameters?.sync_lock_ratio !== undefined && view.parameters?.sync_lock_ratio !== null ? `${(Number(view.parameters.sync_lock_ratio) * 100).toFixed(1)}% sync lock` : 'nominal timing'} · double-click for full screen</small></span></button>;
                    })}</div> : <div className="sstv-empty"><span>▥</span><div><strong>{audioSignals.sstv?.candidate ? 'SSTV tones were detected, but no complete image was recovered' : 'No SSTV VIS transmission detected'}</strong><p>{audioSignals.sstv?.candidate ? 'Scan a longer section or force the expected mode in Audio settings when the VIS header is damaged.' : 'Auto mode looks for the 1900 Hz leader, VIS code, 1200 Hz line sync, and 1500–2300 Hz pixel tones.'}</p></div></div>}
                    {audioSignals.sstv?.headers?.length ? <div className="sstv-header-list"><span>VIS headers</span>{audioSignals.sstv.headers.slice(0, 6).map((header, index) => <div key={`${header.offset_seconds}-${index}`}><strong>{header.mode || header.vis_hex || 'Unknown mode'}</strong><small>{Number(header.offset_seconds || 0).toFixed(3)} s · {header.parity_valid ? 'parity valid' : 'parity damaged'} · {header.confidence !== undefined ? `${(Number(header.confidence) * 100).toFixed(1)}% confidence` : 'confidence unavailable'}{header.frequency_shift_hz ? ` · ${Number(header.frequency_shift_hz).toFixed(1)} Hz tuning shift` : ''}</small></div>)}</div> : null}
                  </section>
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
                      <div className="audio-subheading"><div><p className="eyebrow">Visual evidence</p><h3>Waveform &amp; spectrum</h3></div><span>{diagnosticAudioVisuals.length}</span></div>
                      <div className="audio-visual-grid">
                        {diagnosticAudioVisuals.map((view, index) => {
                          const preview = normalizeUrl(view.preview_url) || (view.artifact_id ? `${API_BASE}/api/jobs/${jobId}/artifacts/${view.artifact_id}/preview` : '');
                          return <button key={view.id || index} title="Double-click to open this image full screen" onDoubleClick={() => openFullscreenVisual({ ...view, preview_url: preview })} onClick={() => { setSelectedVisual({ ...view, preview_url: preview }); setActiveTab('visual'); }}><SafePreviewImage src={preview} alt={view.title || `Audio visual ${index + 1}`} /><span><strong>{view.title || `Audio visual ${index + 1}`}</strong><small>{view.category || 'signal visualization'} · double-click for full screen</small></span></button>;
                        })}
                        {!diagnosticAudioVisuals.length && <div className="empty-state large"><span>≋</span><strong>No spectral image is available</strong><p>For compressed audio, install FFmpeg or SoX and scan again.</p></div>}
                      </div>
                    </section>
                    <aside className="audio-signal-panel">
                      <div className="audio-subheading"><div><p className="eyebrow">Decoded signals</p><h3>Automatic detections</h3></div></div>
                      <div className="audio-signal-cards">
                        <article><span>DTMF</span><strong>{audioSignals.dtmf?.symbols || 'None'}</strong><small>{audioSignals.dtmf?.events?.length || 0} bounded event(s)</small></article>
                        <article><span>Morse</span><strong>{audioSignals.morse?.text || 'None'}</strong><small>{audioSignals.morse?.pattern ? String(audioSignals.morse.pattern).slice(0, 70) : 'No confident keying sequence'}</small></article>
                        <article className={audioSignals.sstv?.images_decoded ? 'success' : audioSignals.sstv?.candidate ? 'warning' : ''}><span>SSTV</span><strong>{audioSignals.sstv?.images_decoded ? `${audioSignals.sstv.images_decoded} image${audioSignals.sstv.images_decoded === 1 ? '' : 's'}` : audioSignals.sstv?.candidate ? 'Signal detected' : 'No transmission'}</strong><small>{audioSignals.sstv?.decoded_modes?.join(', ') || `${audioSignals.sstv?.leader_frames || 0} leader · ${audioSignals.sstv?.sync_frames || 0} sync frames`}</small></article>
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
                        return <button key={view.id || `${view.name}-${index}`} title="Double-click to open this image full screen" onDoubleClick={() => openFullscreenVisual({ ...view, preview_url: preview })} onClick={() => setSelectedVisual({ ...view, preview_url: preview })} className={selectedVisual?.id === view.id ? 'active' : ''}>{preview ? <SafePreviewImage src={preview} alt={view.title || view.name || `Visual derivative ${index + 1}`} /> : <span className="visual-placeholder">◫</span>}<span><strong>{view.title || view.name || `View ${index + 1}`}</strong><small>{view.kind || 'Derived image'} · double-click for full screen</small></span></button>;
                      })}
                      {!filteredVisuals.length && <div className="empty-state large"><span>◫</span><strong>{resultQuery ? 'No visual views match this search' : 'No visual derivatives are available'}</strong><p>{isAudioResult ? 'Built-in WAV visuals or FFmpeg/SoX spectrograms appear here.' : 'Pillow-based views appear here when the optional image engine is installed.'}</p></div>}
                    </div>
                    {selectedVisual && <aside className="visual-focus"><button onClick={() => setSelectedVisual(null)} aria-label="Close visual preview">×</button>{selectedVisual.preview_url ? <SafePreviewImage src={selectedVisual.preview_url} alt={selectedVisual.title || selectedVisual.name || 'Selected visual derivative'} /> : null}<strong>{selectedVisual.title || selectedVisual.name}</strong><p>{selectedVisual.kind || 'Derived visual evidence'}</p>{selectedVisual.preview_url ? <button className="visual-expand-button" onClick={() => openFullscreenVisual(selectedVisual)}>⛶ Open full screen</button> : null}</aside>}
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
                  <div className="section-title"><div><p className="eyebrow">Editable byte evidence</p><h2>Hex editor</h2></div><span>{hexView ? `${formatBytes(hexView.total_size)} · ${hexEdits.size} unsaved edit${hexEdits.size === 1 ? '' : 's'}` : 'Select an artifact'}</span></div>
                  <p className="panel-lede">Edit fixed-size bytes in a reversible draft. The source artifact is never overwritten: integrity checks and a safe image/audio preview update automatically as you type.</p>
                  <div className="hex-toolbar">
                    <label><span>Artifact</span><select value={effectiveHexArtifactId} onChange={(event) => selectHexArtifact(event.target.value)} disabled={!hexArtifactChoices.length}><option value="">Choose an artifact…</option>{hexArtifactChoices.map((artifact) => <option key={artifactId(artifact)} value={artifactId(artifact)}>{artifactName(artifact)} · {formatBytes(artifactSize(artifact))}</option>)}</select></label>
                    <form onSubmit={submitHexSearch} className="hex-search-form"><label><span>Search</span><input value={hexSearchInput} onChange={(event) => setHexSearchInput(event.target.value.slice(0, 256))} placeholder={hexSearchMode === 'hex' ? '89 50 4e 47 or PK:03:04' : 'flag{…} or readable text'} disabled={!effectiveHexArtifactId} /></label><select aria-label="Hex search mode" value={hexSearchMode} onChange={(event) => setHexSearchMode(event.target.value as 'text' | 'hex')} disabled={!effectiveHexArtifactId}><option value="text">Text</option><option value="hex">Hex bytes</option></select><button type="submit" disabled={!effectiveHexArtifactId || hexLoading}>Search</button></form>
                    <div className="hex-offset-control"><label><span>Offset</span><input value={hexOffsetInput} onChange={(event) => setHexOffsetInput(event.target.value.slice(0, 24))} onKeyDown={(event) => { if (event.key === 'Enter') goToHexOffset(); }} disabled={!effectiveHexArtifactId} /></label><button onClick={goToHexOffset} disabled={!effectiveHexArtifactId}>Go</button><button onClick={() => jumpToHexOffset(Math.max(0, hexOffset - 8192))} disabled={!hexView || hexOffset <= 0} aria-label="Previous hex page">←</button><button onClick={() => jumpToHexOffset(hexOffset + 8192)} disabled={!hexView || hexOffset + hexView.length >= hexView.total_size} aria-label="Next hex page">→</button></div><button className="hex-structure-scan-button" onClick={() => void loadHexView(effectiveHexArtifactId, hexOffset, hexSearch, hexSearchMode)} disabled={!effectiveHexArtifactId || hexLoading || Boolean(hexEdits.size)} title={hexEdits.size ? 'Discard the draft before scanning the source artifact.' : 'Re-run format and corruption checks'}>Scan corruption</button>
                  </div>
                  <div className="hex-edit-toolbar">
                    <div className="hex-edit-status" aria-live="polite"><span className={hexEdits.size ? 'draft-dot active' : 'draft-dot'} aria-hidden="true" />{hexEdits.size ? `${hexEdits.size} unsaved byte edit${hexEdits.size === 1 ? '' : 's'}` : 'No unsaved edits'}{hexPreviewBusy ? <small> · updating live checks…</small> : null}</div>
                    <label className="hex-derived-name"><span>Derived filename</span><input value={hexDerivedName} onChange={(event) => setHexDerivedName(event.target.value.slice(0, 180))} placeholder="challenge-edited.png" disabled={!hexEdits.size || hexSaveBusy} /></label>
                    <button onClick={undoHexEdit} disabled={!hexUndo.length || hexSaveBusy} title="Undo (Ctrl/Cmd+Z)">Undo</button>
                    <button onClick={redoHexEdit} disabled={!hexRedo.length || hexSaveBusy} title="Redo (Ctrl/Cmd+Shift+Z)">Redo</button>
                    <button onClick={discardHexEdits} disabled={!hexEdits.size || hexSaveBusy}>Discard</button>
                    <button className="hex-save-button" onClick={() => void saveHexEdits()} disabled={!hexEdits.size || hexSaveBusy || !activeHexArtifact}>{hexSaveBusy ? 'Saving…' : 'Save derived artifact'}</button>
                  </div>
                  {hexError && <div className="error-banner" role="alert"><span>!</span><p>{hexError}</p><button onClick={() => setHexError('')} aria-label="Dismiss hex error">×</button></div>}
                  {hexLoading && <div className="hex-loading"><span className="spinner" />Reading bytes and checking anomalies…</div>}
                  {!hexLoading && !hexArtifactChoices.length && <div className="empty-state large"><span>⌘</span><strong>No artifact is available for hex inspection</strong><p>Run an analysis first so the immutable source and recovered files can be selected.</p></div>}
                  {!hexLoading && hexView && <>
                    <div className="hex-live-preview" aria-live="polite"><div className="hex-live-heading"><div><p className="eyebrow">Live result</p><h3>{hexEdits.size ? 'Edited bytes preview' : 'Original artifact preview'}</h3></div><span className={hexPreviewBusy ? 'preview-state busy' : displayHexPreviewUrl ? 'preview-state ready' : 'preview-state'}>{hexPreviewBusy ? 'Checking…' : displayHexPreviewUrl ? 'Live' : 'No browser preview'}</span></div>{displayHexPreviewUrl && hexPreviewKind === 'image' ? <SafePreviewImage src={displayHexPreviewUrl} alt={hexEdits.size ? 'Live preview of edited bytes' : 'Preview of selected artifact'} className="hex-live-image" /> : null}{displayHexPreviewUrl && hexPreviewKind === 'audio' ? <audio className="hex-live-audio" controls preload="metadata" src={displayHexPreviewUrl} /> : null}{!displayHexPreviewUrl ? <p className="hex-muted">{hexEditPreview?.preview.message || 'Select a supported image or audio artifact to see a browser preview. Structural checks still update for every edited file.'}</p> : null}{hexEdits.size && hexEditPreview?.sha256 ? <small className="hex-live-hash">Edited SHA-256 · <code>{hexEditPreview.sha256}</code></small> : null}</div>
                    <div className="hex-stat-row"><div><strong>{formatHexOffset(hexView.offset)}</strong><small>window start</small></div><div><strong>{formatBytes(hexView.length)}</strong><small>bytes shown</small></div><div><strong>{hexView.search?.match_count || 0}</strong><small>base search matches</small></div><div><strong>{hexEdits.size}</strong><small>unsaved byte edits</small></div></div>
                    <div className="hex-layout">
                      <div className="hex-table" role="grid" aria-label="Editable hex byte window" onKeyDown={handleHexEditorKeyDown}>
                        <div className="hex-table-head" role="row"><span>Offset</span><span>Hex bytes · click a cell to edit</span><span>ASCII</span></div>
                        {hexView.rows.map((row) => {
                          const baseBytes = hexRowBytes(row);
                          const displayedBytes = baseBytes.map((byte, index) => hexEdits.get(row.offset + index)?.value ?? byte);
                          const matched = hexView.matches.some((match) => match.offset < row.offset + row.length && match.offset + match.length > row.offset);
                          return <div className={`hex-row ${matched ? 'matched' : ''}`} role="row" key={row.offset}>
                            <span className="hex-row-offset">{formatHexOffset(row.offset)}</span>
                            <div className="hex-byte-grid" role="gridcell">
                              {baseBytes.map((original, index) => {
                                const offset = row.offset + index;
                                const edited = hexEdits.get(offset);
                                const draft = hexDraftBytes[offset];
                                return <HexByteCell
                                  key={offset}
                                  offset={offset}
                                  original={original}
                                  value={draft ?? formatHexByte(edited?.value ?? original)}
                                  highlighted={hexHoverOffset === offset}
                                  onChange={(value) => handleHexByteDraft(offset, value)}
                                  onBlur={(value) => finishHexByteDraft(offset, value)}
                                  onPaste={(event) => { event.preventDefault(); pasteHexBytes(offset, event.clipboardData.getData('text')); }}
                                  onContextMenu={(event) => openHexContextMenu(event, offset)}
                                  onMouseEnter={() => setHexHoverOffset(offset)}
                                  onMouseLeave={() => setHexHoverOffset((current) => current === offset ? null : current)}
                                />;
                              })}
                            </div>
                            <code className="hex-row-ascii">
                              {displayedBytes.map((byte, index) => {
                                const offset = row.offset + index;
                                const character = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
                                return <span
                                  className={`hex-ascii-char${hexHoverOffset === offset ? ' hovered' : ''}`}
                                  key={offset}
                                  title={`Byte ${formatHexOffset(offset)} · 0x${formatHexByte(byte)}`}
                                  aria-label={`ASCII byte at ${formatHexOffset(offset)}: ${character}`}
                                  onMouseEnter={() => setHexHoverOffset(offset)}
                                  onMouseLeave={() => setHexHoverOffset((current) => current === offset ? null : current)}
                                >{character}</span>;
                              })}
                            </code>
                          </div>;
                        })}
                        {!hexView.rows.length && <div className="hex-empty">The selected offset is at end-of-file.</div>}
                      </div>
                      <aside className="hex-findings"><section className="hex-reference-card"><div className="hex-subheading"><div><p className="eyebrow">Byte signatures</p><h3>Format reference</h3></div><span>{HEX_FORMAT_REFERENCE.length} formats</span></div><div className="hex-reference-table" role="table" aria-label="Image and audio header and trailer reference"><div className="hex-reference-head" role="row"><span>Format</span><span>Header</span><span>Trailer / end</span></div>{HEX_FORMAT_REFERENCE.map((entry) => <article key={entry.format} role="row"><div><strong>{entry.format}</strong><small>{entry.extensions}</small></div><code title={`${entry.format} header`}>{entry.header}</code><code title={`${entry.format} trailer`}>{entry.trailer}</code><p>{entry.structure}. {entry.notes}</p></article>)}</div><p className="hex-reference-note"><code>??</code> means a variable size field; use the format-aware scan below to validate values and boundaries.</p></section>{activeHexIntegrity && <section className="hex-integrity-card"><div className="hex-subheading"><div><p className="eyebrow">Format-aware review{hexEdits.size ? ' · edited draft' : ' · source'}</p><h3>Structure health</h3></div><em className={`integrity-badge ${activeHexIntegrity.verdict}`}>{integrityLabel(activeHexIntegrity.verdict)}</em></div><p className="hex-integrity-summary">{activeHexIntegrity.summary}</p><small className="hex-integrity-format">Expected {activeHexIntegrity.expected_format || 'unknown'} · detected {activeHexIntegrity.detected_format || 'unknown'}{activeHexIntegrity.validation_complete === false ? ' · bounded check' : ''}</small>{activeHexIntegrity.issues?.length ? <div className="hex-integrity-list">{activeHexIntegrity.issues.map((issue, index) => <button key={`${issue.kind}-${issue.offset ?? index}`} onClick={() => issue.offset !== undefined && jumpToHexOffset(Math.max(0, issue.offset - 64))}><div><strong>{issue.title}</strong><em className={issue.severity}>{issue.severity}</em></div>{issue.offset !== undefined ? <small>{formatHexOffset(issue.offset)}{issue.length ? ` · ${formatBytes(issue.length)}` : ''}</small> : null}<p>{issue.description}</p></button>)}</div> : <p className="hex-muted">No confirmed structural errors or warnings were found. Heuristic signals are listed separately.</p>}</section>}<section><div className="hex-subheading"><div><p className="eyebrow">Pattern search</p><h3>Matches</h3></div><span>{hexView.matches.length}</span></div>{hexView.matches.length ? <div className="hex-match-list">{hexView.matches.map((match) => <button key={match.offset} onClick={() => jumpToHexOffset(Math.max(0, match.offset - 64))}><strong>{formatHexOffset(match.offset)}</strong><small>{match.length} byte{match.length === 1 ? '' : 's'} · jump here</small></button>)}</div> : <p className="hex-muted">{hexSearch ? 'No matches found in the base artifact. Save edits as a derived artifact to search its complete bytes.' : 'Enter text or hex bytes above to search.'}</p>}</section><section><div className="hex-subheading"><div><p className="eyebrow">Heuristic leads</p><h3>Anomalies</h3></div><span>{hexView.anomalies.length}</span></div>{hexView.anomalies.length ? <div className="hex-anomaly-list">{hexView.anomalies.map((anomaly, index) => <button key={`${anomaly.kind}-${anomaly.offset}-${index}`} onClick={() => jumpToHexOffset(Math.max(0, anomaly.offset - 64))}><div><strong>{anomaly.title}</strong><em className={anomaly.severity || 'info'}>{anomaly.severity || 'info'}</em></div><small>{formatHexOffset(anomaly.offset)} · {formatBytes(anomaly.length)}</small><p>{anomaly.description}</p></button>)}</div> : <p className="hex-muted">No heuristic anomalies were detected. These are leads, not corruption verdicts.</p>}</section></aside>
                      {hexContextMenu && <div className="hex-context-menu" data-hex-context-menu role="menu" aria-label={`Hex actions for ${formatHexOffset(hexContextMenu.offset)}`} style={{ left: hexContextMenu.x, top: hexContextMenu.y }} onContextMenu={(event) => event.preventDefault()}>
                        <div className="hex-context-heading"><strong>Byte {formatHexOffset(hexContextMenu.offset)}</strong><small>original {formatHexByte(hexContextMenu.original)} · current {formatHexByte(hexContextMenu.value)}</small></div>
                        <button type="button" role="menuitem" onClick={() => { undoHexEdit(); setHexContextMenu(null); }} disabled={!hexUndo.length}><span>Undo last edit</span><kbd>Ctrl/Cmd+Z</kbd></button>
                        <button type="button" role="menuitem" onClick={() => restoreHexByte(hexContextMenu.offset)} disabled={hexContextMenu.value === hexContextMenu.original}><span>Restore this byte</span><kbd>{formatHexByte(hexContextMenu.original)}</kbd></button>
                        <button type="button" role="menuitem" className="danger" onClick={() => deleteHexUnit(hexContextMenu.offset)}><span>Delete unit</span><small>zero 1 byte</small></button>
                        <button type="button" role="menuitem" className="danger" onClick={() => deleteHexBlock(hexContextMenu.blockStart, hexContextMenu.blockLength)}><span>Delete block</span><small>zero {hexContextMenu.blockLength} bytes</small></button>
                        <p>Draft-only action · file length and source bytes stay unchanged.</p>
                      </div>}
                    </div>
                    {activeHexIntegrity && <section className="hex-repair-card"><div className="hex-subheading"><div><p className="eyebrow">Copy-only fixes</p><h3>Repair candidates</h3></div><span>{hexRepairCandidates.length}</span></div><p className="hex-repair-intro">The parser compares the bytes, identifies the format, and proposes only deterministic repairs such as CRC fields or missing end markers. Every repair is saved as a new artifact.</p>{hexRepairCandidates.length ? <div className="hex-repair-list">{hexRepairCandidates.map((candidate) => <article key={candidate.id}><div className="hex-repair-heading"><strong>{candidate.label.replace(/[_-]+/g, ' ')}</strong><em>{(candidate.format || 'format').toUpperCase()}</em></div><p>{candidate.reason}</p><small>{candidate.transformation}</small><div className="hex-repair-meta"><span>{candidate.changed_bytes} byte{candidate.changed_bytes === 1 ? '' : 's'} changed</span><span>{candidate.size_delta >= 0 ? '+' : ''}{candidate.size_delta} bytes</span><span>After: {integrityLabel(candidate.after_integrity?.verdict)}</span></div><button type="button" onClick={() => void saveHexRepair(candidate)} disabled={Boolean(hexEdits.size) || hexRepairBusy || !activeHexArtifact}>{hexRepairBusy ? 'Saving…' : hexEdits.size ? 'Discard draft first' : 'Create repair artifact'}</button></article>)}</div> : <p className="hex-muted">No deterministic repair was found for this format. Review the detected header/trailer and use the editor for a deliberate byte-level patch.</p>}</section>}
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
              <section className="settings-section appearance-settings" aria-labelledby="appearance-settings">
                <div className="settings-section-title"><div><p className="eyebrow">Display preferences</p><h3 id="appearance-settings">Appearance and text size</h3></div><button type="button" onClick={() => setUiPreferences(DEFAULT_UI_PREFERENCES)}>Reset appearance</button></div>
                <div className="appearance-settings-grid">
                  <div className="appearance-control">
                    <span><strong>Color theme</strong><small>Switch the complete workbench, results, and hex editor.</small></span>
                    <div className="theme-choice" role="group" aria-label="Color theme">
                      <button type="button" className={uiPreferences.theme === 'light' ? 'active' : ''} aria-pressed={uiPreferences.theme === 'light'} onClick={() => setUiPreferences((current) => ({ ...current, theme: 'light' }))}><i aria-hidden="true">☀</i>Light</button>
                      <button type="button" className={uiPreferences.theme === 'dark' ? 'active' : ''} aria-pressed={uiPreferences.theme === 'dark'} onClick={() => setUiPreferences((current) => ({ ...current, theme: 'dark' }))}><i aria-hidden="true">◐</i>Dark</button>
                    </div>
                  </div>
                  <div className="appearance-control zoom-preference">
                    <span><strong>Interface zoom</strong><small>Enlarge all text, controls, tool output, and hex bytes.</small></span>
                    <div className="zoom-preference-controls">
                      <button type="button" aria-label="Zoom out interface" disabled={uiPreferences.zoom <= UI_ZOOM_MIN} onClick={() => setUiPreferences((current) => ({ ...current, zoom: normalizeInterfaceZoom(current.zoom - 10) }))}>−</button>
                      <label htmlFor="interface-zoom"><input id="interface-zoom" type="range" min={UI_ZOOM_MIN} max={UI_ZOOM_MAX} step="5" value={uiPreferences.zoom} onChange={(event) => setUiPreferences((current) => ({ ...current, zoom: normalizeInterfaceZoom(event.target.value) }))} /><output htmlFor="interface-zoom" aria-live="polite">{uiPreferences.zoom}%</output></label>
                      <button type="button" aria-label="Zoom in interface" disabled={uiPreferences.zoom >= UI_ZOOM_MAX} onClick={() => setUiPreferences((current) => ({ ...current, zoom: normalizeInterfaceZoom(current.zoom + 10) }))}>＋</button>
                    </div>
                  </div>
                </div>
                <p className="appearance-note">Saved only in this browser. Zoom changes apply immediately and do not alter exported evidence.</p>
              </section>

              <section className="settings-section" aria-labelledby="analysis-switches">
                <div className="settings-section-title"><div><p className="eyebrow">Analysis stages</p><h3 id="analysis-switches">{sectionCopy.settingsLabel} method groups</h3></div><span>{currentConfigurableMethods.filter((item) => scanOptions[item.key]).length}/{currentConfigurableMethods.length} enabled</span></div>
                <div className="method-settings-grid">
                  {currentConfigurableMethods.map((item) => <label className="setting-toggle" key={item.key}><span><strong>{item.title}</strong><small>{item.copy}</small></span><input type="checkbox" checked={scanOptions[item.key]} onChange={(event) => setScanOptions((current) => ({ ...current, [item.key]: event.target.checked }))} /><i aria-hidden="true" /></label>)}
                </div>
              </section>

              <section className="settings-section" aria-labelledby="safety-budgets">
                <div className="settings-section-title"><div><p className="eyebrow">Resource controls</p><h3 id="safety-budgets">Safety budgets</h3></div><button onClick={() => setScanOptions({ ...profileOptionDefaults[profile], evidence_type: evidenceSection })}>Reset {profile}</button></div>
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
                  </> : evidenceSection === 'audio' ? <>
                    <label><span>Analyze duration<small>Decoded seconds, bounded 15–300</small></span><input type="number" min="15" max="300" step="15" value={scanOptions.audio_analysis_seconds} onChange={(event) => setScanOptions((current) => ({ ...current, audio_analysis_seconds: Math.max(15, Math.min(300, Number(event.target.value) || 15)) }))} /></label>
                    <label><span>Spectrogram FFT<small>Frequency/time resolution</small></span><select value={scanOptions.audio_spectrogram_fft} onChange={(event) => setScanOptions((current) => ({ ...current, audio_spectrogram_fft: Number(event.target.value) as ScanOptions['audio_spectrogram_fft'] }))}>{[256, 512, 1024, 2048, 4096].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                    <label><span>Analysis channel<small>Signal used by decoders</small></span><select value={scanOptions.audio_channel_mode} onChange={(event) => setScanOptions((current) => ({ ...current, audio_channel_mode: event.target.value as ScanOptions['audio_channel_mode'] }))}><option value="mix">Mono mix</option><option value="left">Left</option><option value="right">Right</option><option value="difference">Stereo difference</option></select></label>
                    <label><span>PCM bit planes<small>Payload-byte planes plus stereo channel splits</small></span><select value={scanOptions.audio_lsb_bits} onChange={(event) => setScanOptions((current) => ({ ...current, audio_lsb_bits: Number(event.target.value) }))}>{[1, 2, 3, 4, 5, 6, 7, 8].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                    <label><span>SSTV mode<small>Auto VIS or force a damaged transmission</small></span><select value={scanOptions.audio_sstv_mode} disabled={!scanOptions.audio_sstv} onChange={(event) => setScanOptions((current) => ({ ...current, audio_sstv_mode: event.target.value as ScanOptions['audio_sstv_mode'] }))}><option value="auto">Auto-detect VIS</option><option value="robot36">Robot 36</option><option value="robot72">Robot 72</option><option value="martin1">Martin M1</option><option value="martin2">Martin M2</option><option value="scottie1">Scottie S1</option><option value="scottie2">Scottie S2</option><option value="scottiedx">Scottie DX</option><option value="pd120">PD-120</option><option value="pd180">PD-180</option><option value="pd240">PD-240</option></select></label>
                    <label><span>SSTV image ceiling<small>Maximum transmissions decoded, 1–4</small></span><select value={scanOptions.audio_sstv_max_images} disabled={!scanOptions.audio_sstv} onChange={(event) => setScanOptions((current) => ({ ...current, audio_sstv_max_images: Number(event.target.value) }))}>{[1, 2, 3, 4].map((value) => <option key={value} value={value}>{value}</option>)}</select></label>
                    <label className="budget-check"><span>Correct SSTV slant<small>Re-align each line from its 1200 Hz sync</small></span><input type="checkbox" checked={scanOptions.audio_sstv_slant_correction} disabled={!scanOptions.audio_sstv} onChange={(event) => setScanOptions((current) => ({ ...current, audio_sstv_slant_correction: event.target.checked }))} /></label>
                  </> : null}
                </div>
              </section>

              <section className="settings-section" aria-labelledby="external-tools">
                <div className="settings-section-title"><div><p className="eyebrow">Installed integrations</p><h3 id="external-tools">{sectionCopy.toolLabel} tool adapters</h3></div><div className="tool-header-actions"><span>{availableTools}/{relevantCapabilities.length} installed</span><button onClick={refreshToolAvailability} disabled={toolRefreshBusy || toolInstallBusy}>{toolRefreshBusy ? 'Checking…' : 'Refresh availability'}</button><button onClick={() => installMissingTools()} disabled={toolInstallBusy || toolRefreshBusy || !relevantCapabilities.length}>{toolInstallBusy ? 'Installing tools…' : 'Install all missing'}</button></div></div>
                <p className="install-note">One click installs fixed, allowlisted packages non-interactively through Kali WSL or Windows Package Manager—no ZIP extraction or installer walkthrough. {sectionCopy.installNote}</p>
                {toolInstallReport && <div className={`tool-download-report ${toolInstallReport.status || ''}`}><div><strong>{toolInstallReport.message || 'Tool installation finished.'}</strong><small>{toolInstallReport.available_count !== undefined ? `${toolInstallReport.available_count}/${toolInstallReport.requested_count || 0} requested tools detected` : 'Installation report recorded.'}{toolInstallReport.managers?.length ? ` · ${toolInstallReport.managers.join(', ')}` : ''}</small></div></div>}
                {toolInstallReport?.items?.length ? <div className="tool-download-items" aria-label="Tool installation status"><span className="tool-download-items-title">Installation results</span>{toolInstallReport.items.map((item, index) => <div className="tool-download-item" key={`${item.id || 'tool'}-${index}`}><span><strong>{item.id || 'tool'}</strong><small>{item.message || item.status || 'recorded'}{item.channel ? ` · ${item.channel}` : ''}{item.resolved ? ` · ${item.resolved}` : ''}</small>{item.diagnostic ? <details open><summary>Installer diagnostic</summary><pre>{boundedDisplay(item.diagnostic, 2_000)}</pre></details> : null}</span><em className={item.status || ''}>{(item.status || 'unknown').replaceAll('_', ' ')}</em></div>)}</div> : null}
                {evidenceSection === 'corrupted' && webRepairCapabilities.length ? <div className="repair-web-sources" aria-label="Web-sourced repair tools"><div><p className="eyebrow">Web-sourced repair engines</p><strong>Curated upstream tools for damaged files</strong><small>These links document the projects behind the adapters. Installation still uses the fixed local package mappings above; original files remain unchanged.</small></div><div className="repair-web-source-links">{webRepairCapabilities.map((capability) => capability.source_url ? <a key={`${capability.id || capability.executable}-source`} href={capability.source_url} target="_blank" rel="noreferrer noopener">{capability.name || capability.id || capability.executable} ↗</a> : null)}</div></div> : null}
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
            <footer><div><span className="status-dot" /><p><strong>{currentConfigurableMethods.filter((item) => scanOptions[item.key]).length} method groups enabled</strong><small>{scanOptions.max_artifacts} artifacts · {scanOptions.max_recursion_depth} levels · Foremost depth {scanOptions.foremost_depth} · {scanOptions.tool_timeout_seconds}s/tool{evidenceSection === 'image' ? ` · zsteg ${scanOptions.zsteg_mode === 'lsb' ? '--lsb' : '-a'}` : evidenceSection === 'audio' ? ` · ${scanOptions.audio_analysis_seconds}s audio window` : ' · repairs remain copy-only'}</small></p></div><button onClick={() => setShowAdvanced(false)}>Apply settings</button></footer>
          </section>
        </div>
      )}

      {fullscreenVisual?.preview_url && (
        <div className="visual-fullscreen-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && setFullscreenVisual(null)}>
          <section className={`visual-fullscreen-dialog ${fullscreenMode}`} role="dialog" aria-modal="true" aria-labelledby="visual-fullscreen-title">
            <header>
              <div><p className="eyebrow">Verified visual evidence</p><h2 id="visual-fullscreen-title">{fullscreenVisual.title || fullscreenVisual.name || 'Image preview'}</h2></div>
              <div className="visual-fullscreen-actions"><button className={fullscreenMode === 'fit' ? 'active' : ''} onClick={() => setFullscreenMode('fit')}>Fit screen</button><button className={fullscreenMode === 'fill' ? 'active' : ''} onClick={() => setFullscreenMode('fill')}>Fill viewport</button><button className={fullscreenMode === 'pixel' ? 'active' : ''} onClick={() => setFullscreenMode('pixel')}>Actual pixels</button><button className="visual-fullscreen-close" onClick={() => setFullscreenVisual(null)} aria-label="Close full-screen image">×</button></div>
            </header>
            <div className="visual-transform-toolbar" aria-label="Image transform controls">
              <label><span>Zoom</span><input type="range" min="0.25" max="5" step="0.05" value={fullscreenZoom} onChange={(event) => setFullscreenZoom(Number(event.target.value))} /><output>{Math.round(fullscreenZoom * 100)}%</output></label>
              <label><span>Stretch X</span><input type="range" min="0.5" max="2.5" step="0.05" value={fullscreenScaleX} onChange={(event) => setFullscreenScaleX(Number(event.target.value))} /><output>{fullscreenScaleX.toFixed(2)}×</output></label>
              <label><span>Stretch Y</span><input type="range" min="0.5" max="2.5" step="0.05" value={fullscreenScaleY} onChange={(event) => setFullscreenScaleY(Number(event.target.value))} /><output>{fullscreenScaleY.toFixed(2)}×</output></label>
              <label><span>Rhombus X</span><input type="range" min="-35" max="35" step="1" value={fullscreenSkewX} onChange={(event) => setFullscreenSkewX(Number(event.target.value))} /><output>{fullscreenSkewX}°</output></label>
              <label><span>Rhombus Y</span><input type="range" min="-35" max="35" step="1" value={fullscreenSkewY} onChange={(event) => setFullscreenSkewY(Number(event.target.value))} /><output>{fullscreenSkewY}°</output></label>
              <div className="visual-transform-buttons"><button onClick={() => setFullscreenRotation((current) => (current - 90 + 360) % 360)} aria-label="Rotate image counterclockwise 90 degrees">↶ 90°</button><button onClick={() => setFullscreenRotation((current) => (current + 90) % 360)} aria-label="Rotate image clockwise 90 degrees">↷ 90°</button><button onClick={resetFullscreenTransform}>Reset view</button></div>
            </div>
            <div className="visual-fullscreen-stage" onWheel={(event) => { event.preventDefault(); const next = fullscreenZoom + (event.deltaY < 0 ? 0.1 : -0.1); setFullscreenZoom(Math.max(0.25, Math.min(5, Number(next.toFixed(2))))); }}><SafePreviewImage className="visual-transform-image" style={{ transform: `rotate(${fullscreenRotation}deg) skewX(${fullscreenSkewX}deg) skewY(${fullscreenSkewY}deg) scale(${fullscreenZoom * fullscreenScaleX}, ${fullscreenZoom * fullscreenScaleY})` }} src={fullscreenVisual.preview_url} alt={fullscreenVisual.title || fullscreenVisual.name || 'Full-screen visual evidence'} /></div>
            <footer><span>{fullscreenVisual.width && fullscreenVisual.height ? `${fullscreenVisual.width} × ${fullscreenVisual.height} px` : 'Image dimensions unavailable'} · rotation {fullscreenRotation}°</span><span>Mouse wheel to zoom · Esc to close · click outside to return</span></footer>
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
