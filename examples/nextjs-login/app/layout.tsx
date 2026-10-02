import type { ReactNode } from "react";
import "./globals.css";

export const metadata = { title: "IAMKit custom sign-in example" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <main>{children}</main>
      </body>
    </html>
  );
}
