import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import localFont from 'next/font/local'
import "./globals.css";

const tahoma = localFont({
  src: '../fonts/tahoma.ttf',
  variable: '--font-tahoma'
})

export const metadata: Metadata = {
  title: "Scanly",
  description: "A static analysis website",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`h-full antialiased`}
    >
      <body className={`${tahoma.className} font-bold font-[#875F6B] min-h-full flex flex-col bg-[#fff9e6]`}>{children}</body>
    </html>
  );
}
