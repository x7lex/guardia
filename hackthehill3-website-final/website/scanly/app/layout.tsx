import type { Metadata } from "next";
import localFont from "next/font/local";
import "./globals.css";
import BackgroundMusic from "@/components/background-music";

const tahoma = localFont({
  src: "../fonts/tahoma.ttf",
  variable: "--font-tahoma",
});

export const metadata: Metadata = {
  title: "Guardia",
  description: "A static analysis website",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`h-full antialiased`}>
      <body className={`${tahoma.className} min-h-full flex flex-col`}>
        <BackgroundMusic />
        {children}
      </body>
    </html>
  );
}
