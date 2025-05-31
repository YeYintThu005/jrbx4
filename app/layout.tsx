import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'JrBX4 Portfolio',
  description: 'Contact me',
  generator: 'Next.js',
  openGraph: {
    title: 'JrBX4 Portfolio',
    description: 'Explore my portfolio and contact me for projects.',
    url: 'https://jrbx4.vercel.app',
    siteName: 'JrBX4',
    images: [
      {
        url: 'https://jrbx4.vercel.app/og-image.png', // Replace with your image URL
        width: 1200,
        height: 630,
        alt: 'JrBX4 Preview',
      },
    ],
    locale: 'en_US',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'JrBX4 Portfolio',
    description: 'Explore my portfolio and contact me for projects.',
    images: ['https://jrbx4.vercel.app/og-image.png'], // Same image URL
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
