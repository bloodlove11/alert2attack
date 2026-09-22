import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Port 5173 is not incidental: it is the origin the API allows by default
// (DEFAULT_CORS_ORIGINS in alert2attack.api.app). Change one and change the other.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
  },
});
