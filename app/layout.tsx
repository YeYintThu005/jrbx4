import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'JrBX4 Portfolio',
  description: 'Contact me',
  generator: 'Next.js',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
