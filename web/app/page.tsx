'use client';

import { type CSSProperties, type DragEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react';

type Profile = 'quick' | 'balanced' | 'deep';
type Screen = 'setup' | 'running' | 'results';
type ResultTab = 'overview' | 'candidates' | 'artifacts' | 'visual' | 'metadata' | 'methods';

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
  findings?: Finding[];
  methods?: MethodRun[];
  coverage?: MethodRun[] | Record<string, unknown>;
  visual_views?: VisualView[];
  metadata?: Record<string, unknown> | Array<Record<string, unknown>>;
  structure?: unknown;
  logs?: unknown[];
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

type Capability = { id?: string; name?: string; available?: boolean; version?: string; category?: string };
type ActivityItem = { at: string; message: string; stage?: string };

const API_BASE = (
  process.env.NEXT_PUBLIC_API_URL
  || (typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:8000` : 'http://localhost:8000')
).replace(/\/$/, '');
const TERMINAL = new Set(['completed', 'succeeded', 'partial', 'failed', 'cancelled', 'expired']);
const methodGroups = [
  { title: 'Metadata', copy: 'EXIF, XMP, IPTC, ICC', tone: 1 },
  { title: 'Structure', copy: 'Chunks, markers, trailers', tone: 2 },
  { title: 'Steganography', copy: 'LSB, channels, JPEG', tone: 3 },
  { title: 'Vision', copy: 'OCR and barcodes', tone: 4 },
];
const profiles: Array<{ id: Profile; symbol: string; name: string; copy: string; tag: string }> = [
  { id: 'quick', symbol: '↯', name: 'Quick', copy: 'Core clues with minimal transforms', tag: 'Fast' },
  { id: 'balanced', symbol: '✦', name: 'Balanced', copy: 'Best coverage for most CTFs', tag: 'Recommended' },
  { id: 'deep', symbol: '◎', name: 'Deep', copy: 'Carving, recursion and repairs', tag: 'Thorough' },
];
const resultTabs: Array<{ id: ResultTab; label: string }> = [
  { id: 'overview', label: 'Overview' },
  { id: 'candidates', label: 'Flag candidates' },
  { id: 'artifacts', label: 'Artifacts' },
  { id: 'visual', label: 'Visual lab' },
  { id: 'metadata', label: 'Metadata' },
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
function evidenceText(value: unknown) {
  if (typeof value === 'string') return value;
  if (value && typeof value === 'object') return Object.entries(value).map(([key, entry]) => `${key}: ${String(entry)}`).join(' · ');
  return '';
}

async function readJson(response: Response) {
  if (response.ok) return response.json();
  let message = `Request failed (${response.status})`;
  try {
    const data = await response.json();
    message = data?.detail?.message || data?.detail || data?.error?.message || data?.error || data?.message || message;
    if (typeof message !== 'string') message = `Request failed (${response.status})`;
  } catch { /* keep the generic safe message */ }
  throw new Error(message);
}

export default function Home() {
  const fileInput = useRef<HTMLInputElement>(null);
  const [screen, setScreen] = useState<Screen>('setup');
  const [profile, setProfile] = useState<Profile>('balanced');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [flagPrefix, setFlagPrefix] = useState('');
  const [password, setPassword] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [recentJobs, setRecentJobs] = useState<Job[]>([]);
  const [capabilities, setCapabilities] = useState<Capability[]>([]);
  const [engineOnline, setEngineOnline] = useState<boolean | null>(null);
  const [error, setError] = useState('');
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [activeTab, setActiveTab] = useState<ResultTab>('overview');
  const [candidateFilter, setCandidateFilter] = useState<'all' | 'high' | 'medium' | 'low'>('all');
  const [selectedVisual, setSelectedVisual] = useState<VisualView | null>(null);

  const refreshRecent = useCallback(async () => {
    try {
      const payload = await readJson(await fetch(`${API_BASE}/api/jobs`, { cache: 'no-store' }));
      setRecentJobs(Array.isArray(payload) ? payload : payload.items || payload.jobs || []);
    } catch { /* the engine indicator already explains offline state */ }
  }, []);

  useEffect(() => {
    let alive = true;
    Promise.all([
      fetch(`${API_BASE}/api/health`, { cache: 'no-store' }).then(readJson),
      fetch(`${API_BASE}/api/capabilities`, { cache: 'no-store' }).then(readJson),
    ]).then(([, capabilityPayload]) => {
      if (!alive) return;
      setEngineOnline(true);
      setCapabilities(Array.isArray(capabilityPayload) ? capabilityPayload : capabilityPayload.capabilities || capabilityPayload.tools || []);
      refreshRecent();
    }).catch(() => alive && setEngineOnline(false));
    return () => { alive = false; };
  }, [refreshRecent]);

  const refreshJob = useCallback(async (id: string) => {
    if (!id) return;
    try {
      const next = await readJson(await fetch(`${API_BASE}/api/jobs/${id}`, { cache: 'no-store' })) as Job;
      setJob(next);
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
          const envelope = JSON.parse(event.data);
          const payload = envelope?.data && typeof envelope.data === 'object' ? envelope.data : envelope;
          const message = payload.message || payload.detail?.message || payload.stage || payload.status;
          if (message) setActivity((current) => [...current.slice(-19), { at: envelope.created_at || new Date().toISOString(), message: String(message), stage: payload.stage }]);
          if (payload.job) setJob(payload.job);
          else if (payload.status || payload.progress !== undefined || payload.stage) setJob((current) => current ? { ...current, ...payload } : current);
          if (event.type === 'terminal' || TERMINAL.has(String(payload.status || payload.job?.status || '').toLowerCase())) poll();
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
  const candidates = useMemo(() => getCandidates(result).slice().sort((a, b) => scoreOf(b) - scoreOf(a)), [result]);
  const artifacts = useMemo(() => job?.artifacts?.length ? job.artifacts : getArtifacts(result), [job?.artifacts, result]);
  const methods = useMemo(() => getMethods(result), [result]);
  const visuals = useMemo(() => {
    const publicByEngineId = new Map<string, Artifact>();
    for (const artifact of artifacts) {
      const engineId = artifact.metadata?.id;
      if (typeof engineId === 'string') publicByEngineId.set(engineId, artifact);
    }
    return getVisuals(result).map((view) => {
      const publicArtifact = view.artifact_id ? publicByEngineId.get(view.artifact_id) : undefined;
      return publicArtifact ? {
        ...view,
        artifact_id: artifactId(publicArtifact),
        preview_url: publicArtifact.preview_url,
      } : view;
    });
  }, [artifacts, result]);
  const findings = useMemo(() => result?.findings || [], [result]);
  const filteredCandidates = candidateFilter === 'all' ? candidates : candidates.filter((candidate) => confidenceBand(candidate) === candidateFilter);
  const availableTools = capabilities.filter((capability) => capability.available === true).length;
  const armedMethodCount = 8 + availableTools;

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
  }

  async function openRecent(recent: Job) {
    setJob(recent);
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
          <button className="nav-item active" onClick={resetScan}><span>◫</span>Image</button>
          <button className="nav-item disabled" disabled><span>≋</span>Audio<em>Soon</em></button>
          <button className="nav-item disabled" disabled><span>⌁</span>Corrupted files<em>Soon</em></button>
          <p className="nav-label second">Workspace</p>
          <button className="nav-item" onClick={() => document.getElementById('recent-scans')?.scrollIntoView({ behavior: 'smooth' })}><span>◷</span>Recent scans</button>
          <button className="nav-item" onClick={() => setShowAdvanced(true)}><span>⌘</span>Method library</button>
        </nav>

        <div className="recent-mini" id="recent-scans">
          {recentJobs.slice(0, 3).map((recent) => (
            <button key={getJobId(recent)} onClick={() => openRecent(recent)}>
              <span className={`mini-status ${recent.status}`} />
              <span><strong>{jobName(recent) || 'Image scan'}</strong><small>{recent.status}</small></span>
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
              <div><p className="eyebrow">Image forensics</p><h1>Find what the pixels are hiding.</h1></div>
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
                  <input ref={fileInput} className="sr-only" type="file" accept=".png,.apng,.jpg,.jpeg,.gif,.bmp,.webp,.tif,.tiff,.ico,application/octet-stream" onChange={(event) => selectFile(event.target.files?.[0])} />
                  {!selectedFile ? (
                    <>
                      <div className="upload-icon" aria-hidden="true"><span>↑</span></div>
                      <p className="card-kicker">Start an investigation</p>
                      <h2>Drop an image here</h2>
                      <p className="upload-copy">PNG, JPEG, GIF, BMP, WebP, TIFF or ICO · up to 100 MB</p>
                      <button className="choose-button" onClick={(event) => { event.stopPropagation(); fileInput.current?.click(); }}>Choose evidence file</button>
                      <p className="evidence-note"><span>◇</span>The original is hashed and never modified</p>
                    </>
                  ) : (
                    <>
                      <div className="file-seal" aria-hidden="true"><span>◫</span><i>Evidence</i></div>
                      <p className="card-kicker">Evidence selected</p>
                      <h2 className="file-name">{selectedFile.name}</h2>
                      <div className="file-facts"><span>{formatBytes(selectedFile.size)}</span><span>SHA-256 on ingest</span><span>Type verified by content</span></div>
                      <div className="file-actions">
                        <button className="choose-button" onClick={(event) => { event.stopPropagation(); startScan(); }}>Analyze image <span>→</span></button>
                        <button className="replace-button" onClick={(event) => { event.stopPropagation(); fileInput.current?.click(); }}>Replace</button>
                      </div>
                      <p className="evidence-note"><span>◇</span>Preview waits for the sandboxed safe renderer</p>
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
                    <button key={item.id} className={`profile-card ${profile === item.id ? 'selected' : ''}`} onClick={() => setProfile(item.id)} aria-pressed={profile === item.id}>
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
                  <button className="password-toggle" onClick={() => setShowPassword((open) => !open)}>{showPassword ? 'Hide passphrase' : '+ Add a stego passphrase'}</button>
                  {showPassword && <input className="password-input" type="password" value={password} autoComplete="off" onChange={(event) => setPassword(event.target.value.slice(0, 256))} placeholder="Optional passphrase" />}
                </div>
                {recentJobs.length > 0 && (
                  <section className="mobile-recent-scans" aria-labelledby="mobile-recent-title">
                    <div><p className="eyebrow">Workspace</p><h2 id="mobile-recent-title">Recent investigations</h2></div>
                    <div>
                      {recentJobs.slice(0, 5).map((recent) => (
                        <button key={getJobId(recent)} onClick={() => openRecent(recent)}>
                          <span className={`mini-status ${recent.status}`} />
                          <span><strong>{jobName(recent) || 'Image scan'}</strong><small>{formatDate(recent.updated_at)}</small></span>
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
                  {methodGroups.map((method, index) => (
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
                  <button className="password-toggle" onClick={() => setShowPassword((open) => !open)}>{showPassword ? 'Hide passphrase' : '+ Add a stego passphrase'}</button>
                  {showPassword && <input className="password-input" type="password" value={password} autoComplete="off" onChange={(event) => setPassword(event.target.value.slice(0, 256))} placeholder="Optional passphrase" />}
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
                <div><p className="eyebrow">Investigation complete</p><h1>{jobName(job) || selectedFile?.name || 'Image analysis'}</h1></div>
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
              <section className="no-candidate-hero"><span>◇</span><div><strong>No high-confidence flag was found</strong><p>The completed coverage remains available below. Try Deep mode, a challenge prefix, or a known passphrase.</p></div></section>
            )}

            <nav className="result-tabs" aria-label="Analysis result sections">
              {resultTabs.map((tab) => <button key={tab.id} className={activeTab === tab.id ? 'active' : ''} onClick={() => setActiveTab(tab.id)}>{tab.label}{tab.id === 'candidates' && <span>{candidates.length}</span>}{tab.id === 'artifacts' && <span>{artifacts.length}</span>}</button>)}
            </nav>

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
                      {findings.slice(0, 8).map((finding, index) => (
                        <article key={finding.id || `${finding.title}-${index}`}>
                          <span className="finding-index">{String(index + 1).padStart(2, '0')}</span>
                          <div><strong>{finding.title || finding.category || 'Forensic finding'}</strong><p>{finding.description || finding.summary || finding.evidence || 'Evidence recorded by the analysis engine.'}</p><small>{finding.method_id || finding.method || finding.category}{finding.offset !== undefined ? ` · offset 0x${finding.offset.toString(16)}` : ''}</small></div>
                        </article>
                      ))}
                      {!findings.length && <div className="empty-state"><span>✓</span><strong>No structural warnings were reported</strong><p>Review method coverage for skipped or unavailable tools.</p></div>}
                    </div>
                  </section>
                </div>
              )}

              {activeTab === 'candidates' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">Ranked evidence</p><h2>Flag candidates</h2></div><div className="filter-pills">{(['all', 'high', 'medium', 'low'] as const).map((filter) => <button key={filter} className={candidateFilter === filter ? 'active' : ''} onClick={() => setCandidateFilter(filter)}>{filter}</button>)}</div></div>
                  <div className="candidate-list">
                    {filteredCandidates.map((candidate, index) => (
                      <article className="candidate-card" key={candidate.id || `${candidateValue(candidate)}-${index}`}>
                        <div className={`score-orb ${confidenceBand(candidate)}`}><strong>{scoreOf(candidate)}</strong><small>%</small></div>
                        <div className="candidate-main"><div><span className={`confidence-chip ${confidenceBand(candidate)}`}>{confidenceBand(candidate)} confidence</span><small>Candidate {String(index + 1).padStart(2, '0')}</small></div><code>{candidateValue(candidate)}</code><p>{candidateEvidence(candidate)}</p>{candidateTransformChain(candidate).length ? <div className="transform-chain">{candidateTransformChain(candidate).map((step) => <span key={step}>{step}</span>)}</div> : null}</div>
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
                  <div className="artifact-table" role="table" aria-label="Recovered artifacts">
                    <div className="artifact-head" role="row"><span>Name</span><span>Type</span><span>Size</span><span>SHA-256</span><span /></div>
                    {artifacts.map((artifact, index) => {
                      const id = artifactId(artifact);
                      const download = normalizeUrl(artifact.download_url) || `${API_BASE}/api/jobs/${jobId}/artifacts/${id}?download=1`;
                      return <div className="artifact-row" role="row" key={id || index} style={{ '--depth': Math.min(artifactDepth(artifact), 4) } as CSSProperties}><span><i>{artifact.parent_id || artifactDepth(artifact) ? '└' : '◆'}</i><strong>{artifactName(artifact)}</strong><small>{artifactOrigin(artifact)}</small></span><span><em>{artifactMediaType(artifact)}</em></span><span>{formatBytes(artifactSize(artifact))}</span><span className="mono">{artifact.sha256?.slice(0, 12) || '—'}</span><a href={download} download aria-label={`Download ${artifactName(artifact)}`}>↓</a></div>;
                    })}
                    {!artifacts.length && <div className="empty-state large"><span>⌁</span><strong>No child artifacts were recovered</strong><p>The original evidence and method logs are still included in the report.</p></div>}
                  </div>
                </section>
              )}

              {activeTab === 'visual' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">Pixel laboratory</p><h2>Channels, bit planes &amp; frames</h2></div><span>{visuals.length} safe previews</span></div>
                  <div className="visual-layout">
                    <div className="visual-grid">
                      {visuals.map((view, index) => {
                        const preview = normalizeUrl(view.preview_url) || (view.artifact_id ? `${API_BASE}/api/jobs/${jobId}/artifacts/${view.artifact_id}/preview` : '');
                        return <button key={view.id || `${view.name}-${index}`} onClick={() => setSelectedVisual({ ...view, preview_url: preview })} className={selectedVisual?.id === view.id ? 'active' : ''}>{preview ? <SafePreviewImage src={preview} alt={view.title || view.name || `Visual derivative ${index + 1}`} /> : <span className="visual-placeholder">◫</span>}<span><strong>{view.title || view.name || `View ${index + 1}`}</strong><small>{view.kind || 'Derived image'}</small></span></button>;
                      })}
                      {!visuals.length && <div className="empty-state large"><span>◫</span><strong>No visual derivatives are available</strong><p>Pillow-based views appear here when the optional image engine is installed.</p></div>}
                    </div>
                    {selectedVisual && <aside className="visual-focus"><button onClick={() => setSelectedVisual(null)} aria-label="Close visual preview">×</button>{selectedVisual.preview_url ? <SafePreviewImage src={selectedVisual.preview_url} alt={selectedVisual.title || selectedVisual.name || 'Selected visual derivative'} /> : null}<strong>{selectedVisual.title || selectedVisual.name}</strong><p>{selectedVisual.kind || 'Derived visual evidence'}</p></aside>}
                  </div>
                </section>
              )}

              {activeTab === 'metadata' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">Parsed properties</p><h2>Metadata &amp; structure</h2></div><span>Original values preserved</span></div>
                  <div className="metadata-grid">
                    {Object.entries(Array.isArray(result?.metadata) ? result?.metadata[0] || {} : result?.metadata || {}).map(([key, value]) => <div key={key}><span>{key.replace(/([A-Z])/g, ' $1').replace(/_/g, ' ')}</span><strong>{typeof value === 'object' ? JSON.stringify(value) : String(value)}</strong></div>)}
                    {!Object.keys(Array.isArray(result?.metadata) ? result?.metadata[0] || {} : result?.metadata || {}).length && <div className="empty-state large"><span>◇</span><strong>No structured metadata was returned</strong><p>Raw strings and tool output remain available in the exported report.</p></div>}
                  </div>
                  {result?.structure !== undefined && <details className="raw-details"><summary>Raw structure report</summary><pre>{JSON.stringify(result.structure, null, 2)}</pre></details>}
                </section>
              )}

              {activeTab === 'methods' && (
                <section className="tab-panel">
                  <div className="section-title"><div><p className="eyebrow">Coverage statement</p><h2>Every applicable method</h2></div><span>{methods.length} recorded</span></div>
                  <div className="coverage-list">
                    {methods.map((method, index) => <article key={method.id || `${methodName(method)}-${index}`}><span className={`coverage-status ${method.status || 'unknown'}`}>{['success', 'completed', 'succeeded', 'no_findings'].includes((method.status || '').toLowerCase()) ? '✓' : ['failed', 'tool_error', 'timeout'].includes((method.status || '').toLowerCase()) ? '!' : '·'}</span><div><strong>{methodName(method)}</strong><p>{method.summary || method.error || 'Method completed without additional commentary.'}</p><small>{method.version ? `v${method.version} · ` : ''}{formatDuration(method.duration_ms)}{method.findings !== undefined ? ` · ${method.findings} findings` : ''}</small></div><em>{method.status || 'recorded'}</em></article>)}
                    {!methods.length && <div className="empty-state large"><span>⌘</span><strong>Coverage records are not available</strong><p>The downloadable report may contain raw tool execution details.</p></div>}
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
            <header><div><p className="eyebrow">Method library</p><h2 id="method-title">What Forenscope will run</h2></div><button onClick={() => setShowAdvanced(false)} aria-label="Close method library">×</button></header>
            <p className="modal-intro">Methods are routed by detected content, not the filename. Missing optional tools are reported transparently and never fail the complete scan.</p>
            <div className="method-catalog">
              {[
                ['Fingerprint & raw bytes', 'SHA-256 · libmagic · ASCII/UTF-16 strings · entropy · signature carving'],
                ['Metadata', 'ExifTool · EXIF · XMP · IPTC · ICC · comments · embedded thumbnails'],
                ['Structure & integrity', 'PNG chunks/CRC · JPEG markers · GIF frames · BMP padding · RIFF · TIFF IFDs · ICO children'],
                ['Spatial steganography', 'zsteg · RGB/alpha channels · bit planes 0–7 · palette indices · LSB text streams'],
                ['JPEG steganography', 'Stegseek · Steghide-compatible extraction · marker trailers · optional passwords'],
                ['Vision', 'Tesseract OCR · QR/barcodes · rotations · thresholds · animation frames'],
                ['Carving & decoding', 'Binwalk signatures · exact trailers · Base encodings · compression · bounded recursion'],
                ['Repair laboratory', 'Auditable PNG/JPEG/GIF/BMP repair copies; the original is never modified'],
              ].map(([title, copy], index) => <article key={title}><span>{String(index + 1).padStart(2, '0')}</span><div><strong>{title}</strong><p>{copy}</p></div><em>{profile === 'quick' && index > 4 ? 'Limited' : profile === 'deep' ? 'Deep' : 'Enabled'}</em></article>)}
            </div>
            <footer><div><span className="status-dot" /><p><strong>Safety budget active</strong><small>100 MB input · bounded artifacts · no network</small></p></div><button onClick={() => setShowAdvanced(false)}>Done</button></footer>
          </section>
        </div>
      )}
    </main>
  );
}
