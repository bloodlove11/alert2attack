import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ErrorBox, Panel } from "../components/ui";
import { api, setBearerToken } from "../lib/api";

/**
 * Shown only when the API says authentication is enabled and no token is held.
 *
 * The API is open by default (local-first, loopback-bound), so on a normal dev
 * checkout this never renders. The token goes into module memory, not
 * localStorage — see the note in lib/api.ts.
 */
export function LoginGate({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("");

  const { data: auth, isPending } = useQuery({
    queryKey: ["me"],
    queryFn: () => api.me(),
    retry: false,
  });

  const login = useMutation({
    mutationFn: () => api.login(username, password),
    onSuccess: (token) => {
      setBearerToken(token.access_token);
      setPassword("");
      // Every query so far failed with a 401; refetch them now.
      void queryClient.invalidateQueries();
    },
  });

  if (isPending) return null;
  if (!auth?.auth_enabled || auth.authenticated) return <>{children}</>;

  return (
    <div className="mx-auto mt-24 max-w-sm px-6">
      <Panel className="p-5">
        <h1 className="text-lg font-semibold">alert2attack Console</h1>
        <p className="mt-1 text-xs text-dim">This API requires a sign-in.</p>

        <form
          className="mt-4 space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            login.mutate();
          }}
        >
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            className="w-full rounded border border-edge bg-ink px-3 py-1.5 text-sm"
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            placeholder="Password"
            className="w-full rounded border border-edge bg-ink px-3 py-1.5 text-sm placeholder:text-dim/60"
          />
          <button
            type="submit"
            disabled={login.isPending || !password}
            className="w-full rounded border border-accent/40 bg-accent/15 px-3 py-1.5 text-sm text-accent hover:bg-accent/25 disabled:opacity-50"
          >
            {login.isPending ? "Signing in…" : "Sign in"}
          </button>
        </form>

        {login.error ? (
          <div className="mt-3">
            <ErrorBox error={login.error} />
          </div>
        ) : null}

        <p className="mt-4 text-[11px] text-dim">
          Demo-grade auth: one configured operator, no user table, no roles. A real
          deployment puts this behind the organisation&rsquo;s identity provider.
        </p>
      </Panel>
    </div>
  );
}
