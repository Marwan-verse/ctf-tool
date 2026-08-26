import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({ variable: '--font-geist-sans', subsets: ['latin'] });
const geistMono = Geist_Mono({ variable: '--font-geist-mono', subsets: ['latin'] });

export const metadata: Metadata = {
  metadataBase: new URL('http://localhost:3000'),
  title: 'Forenscope — CTF Media Forensics',
  description: 'A private, local-first image and audio forensics workbench for CTF investigations.',
  openGraph: {
    title: 'Forenscope — CTF Media Forensics',
    description: 'Find what pixels and waveforms are hiding with a private, local-first forensic workbench.',
    type: 'website',
    images: [{ url: '/og.png', width: 1672, height: 941, alt: 'Forenscope media forensics workbench' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Forenscope — CTF Media Forensics',
    description: 'Find what pixels and waveforms are hiding with a private, local-first forensic workbench.',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body>
    </html>
  );
}
