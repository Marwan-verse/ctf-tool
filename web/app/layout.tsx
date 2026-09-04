import type { Metadata } from 'next';
import { Geist, Geist_Mono } from 'next/font/google';
import './globals.css';

const geistSans = Geist({ variable: '--font-geist-sans', subsets: ['latin'] });
const geistMono = Geist_Mono({ variable: '--font-geist-mono', subsets: ['latin'] });

export const metadata: Metadata = {
  metadataBase: new URL('http://localhost:3000'),
  title: 'Remanence — CTF File Forensics',
  description: 'A private, local-first file-forensics workbench for CTF investigations.',
  applicationName: 'Remanence',
  icons: {
    icon: '/remanence-logo.png',
    apple: '/remanence-logo.png',
  },
  openGraph: {
    title: 'Remanence — CTF File Forensics',
    description: 'Find what files are hiding with a private, local-first forensic workbench.',
    type: 'website',
    images: [{ url: '/remanence-logo.png', width: 1200, height: 1200, alt: 'Remanence CTF forensics logo' }],
  },
  twitter: {
    card: 'summary',
    title: 'Remanence — CTF File Forensics',
    description: 'Find what files are hiding with a private, local-first forensic workbench.',
    images: ['/remanence-logo.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className={`${geistSans.variable} ${geistMono.variable}`}>{children}</body>
    </html>
  );
}
