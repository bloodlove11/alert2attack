import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { CasePage } from "./features/CasePage";
import { LoginGate } from "./features/LoginGate";
import { QueuePage } from "./features/QueuePage";
import { SearchPage } from "./features/SearchPage";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Scenarios are static files on disk; investigations change only when one
      // is run. Neither benefits from refetching every time a window refocuses.
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      retry: 1,
    },
  },
});

const root = document.getElementById("root");
if (!root) throw new Error("#root is missing from index.html");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <LoginGate>
          <Routes>
            <Route path="/" element={<QueuePage />} />
            <Route path="/cases/:scenarioId" element={<CasePage />} />
            <Route path="/search" element={<SearchPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </LoginGate>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
